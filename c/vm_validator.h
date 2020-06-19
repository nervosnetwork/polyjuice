#include <evmc/evmc.h>

#define CSAL_VALIDATOR_TYPE 1
#include "validator.h"
#include "secp256k1_helper.h"

int check_script_code(const uint8_t *script_data_a,
                      const size_t script_size_a,
                      const uint8_t *script_data_b,
                      const size_t script_size_b,
                      bool *matched) {
  if (script_size_a != script_size_b) {
    *matched = false;
    return 0;
  }

  mol_seg_t script_seg_a;
  mol_seg_t script_seg_b;

  script_seg_a.ptr = (uint8_t *)script_data_a;
  script_seg_a.size = script_size_a;
  if (MolReader_Script_verify(&script_seg_a, false) != MOL_OK) {
    return ERROR_INVALID_DATA;
  }
  script_seg_b.ptr = (uint8_t *)script_data_b;
  script_seg_b.size = script_size_b;
  if (MolReader_Script_verify(&script_seg_b, false) != MOL_OK) {
    return ERROR_INVALID_DATA;
  }
  mol_seg_t code_hash_seg_a = MolReader_Script_get_code_hash(&script_seg_a);
  mol_seg_t code_hash_seg_b = MolReader_Script_get_code_hash(&script_seg_b);
  if (code_hash_seg_a.size != code_hash_seg_b.size ||
      memcmp(code_hash_seg_a.ptr, code_hash_seg_b.ptr, code_hash_seg_a.size) != 0) {
    *matched = false;
    return 0;
  }
  mol_seg_t hash_type_seg_a = MolReader_Script_get_hash_type(&script_seg_a);
  mol_seg_t hash_type_seg_b = MolReader_Script_get_hash_type(&script_seg_b);
  if (hash_type_seg_a.size != hash_type_seg_b.size ||
      memcmp(hash_type_seg_a.ptr, hash_type_seg_b.ptr, hash_type_seg_a.size) != 0) {
    *matched = false;
    return 0;
  }
  *matched = true;
  return 0;
}

#define MAX_CONTRACT_COUNT 64

typedef struct {
  evmc_address destination;
  size_t program_index;
} call_record;

typedef struct contract_program {
  size_t total_size;
  uint8_t *signature;
  /* program part */
  size_t program_len;
  evmc_call_kind kind;
  uint32_t flags;
  uint32_t depth;
  evmc_address tx_origin;
  evmc_address sender;
  evmc_address destination;
  size_t code_size;
  uint8_t *code_data;
  size_t input_size;
  uint8_t *input_data;

  /* Other data */
  size_t return_data_size;
  uint8_t *return_data;
  evmc_address beneficiary;
  size_t calls_count;
  size_t call_index;
  call_record *calls;
  struct contract_program *next_program;
  struct contract_program *prev_program;
} contract_program;

typedef struct {
  bool is_main;
  evmc_address address;
  uint8_t *witness_buf;
  size_t witness_size;
  /* if CREATE, update this field after first call */
  uint8_t *code_data;
  size_t code_size;
  /* Variable */
  contract_program *head_program;
  contract_program *current_program;
  size_t program_count;
  size_t program_index;
} contract_info;

static bool global_touched = false;
static contract_info global_info_list[MAX_CONTRACT_COUNT];
static size_t global_info_count = 0;
static evmc_address global_tx_origin{};
static evmc_address global_current_contract;
static bool global_current_is_main = false;

int call_record_load(call_record *record, const uint8_t *buf, const size_t buf_size) {
  if (buf_size < 24) {
    ckb_debug("not enough data to parse call_record");
    return -99;
  }

  record->destination = *(evmc_address *)buf;
  uint32_t index = *(uint32_t *)(buf + 20);
  record->program_index = (size_t)index;
  debug_print_data("[call.destination]", record->destination.bytes, 20);
  debug_print_int("[call.program_index]", record->program_index);
  return 0;
}

int contract_program_load(contract_program *program, const uint8_t *buf, const size_t buf_size) {
  const uint32_t source_size = *(uint32_t *)buf;
  if (source_size > buf_size) {
    ckb_debug("not enough data to parse program");
    return -99;
  }
  const uint8_t *source = buf + 4;
  const uint8_t *signature = source;
  debug_print_data("load signature", signature, 65);
  const uint32_t program_len = *(uint32_t *)(source + SIGNATURE_LEN);
  const uint8_t call_kind = source[CALL_KIND_OFFSET];
  const uint32_t flags = *(uint32_t *)(source + FLAGS_OFFSET);
  const uint32_t depth = *(uint32_t *)(source + DEPTH_OFFSET);
  const evmc_address tx_origin = *(evmc_address *)(source + TX_ORIGIN_OFFSET);
  const evmc_address sender = *(evmc_address *)(source + SENDER_OFFSET);
  const evmc_address destination = *(evmc_address *)(source + DESTINATION_OFFSET);
  const uint32_t code_size = *(uint32_t *)(source + CODE_OFFSET);
  const uint8_t *code_data = (uint8_t *)(source + (CODE_OFFSET + 4));
  debug_print_int("load code_size", code_size);
  debug_print_data("load code_data", code_data, code_size);
  const uint32_t input_size = *(uint32_t *)(code_data + code_size);
  const uint8_t *input_data = input_size > 0 ? code_data + (code_size + 4) : NULL;
  debug_print_int("load input_size", input_size);
  debug_print_data("load input_data", input_data, input_size);

  const uint8_t *other_data = source + SIGNATURE_LEN + PROGRAM_LEN + program_len;
  const uint32_t return_data_size = *(uint32_t *)other_data;
  const uint8_t *return_data = other_data + 4;
  debug_print_int("load return_data_size", return_data_size);
  debug_print_data("load return_data", return_data, return_data_size);
  const evmc_address beneficiary = *(evmc_address *)(return_data + return_data_size);
  const uint32_t calls_count = *(uint32_t *)(return_data + return_data_size + 20);
  const uint8_t *calls_base = return_data + return_data_size + 20 + 4;
  const size_t source_total_size = calls_base - buf + calls_count * 24;
  if (source_total_size > buf_size) {
    ckb_debug("not enough data to parse program");
    return -99;
  }
  if (source_size + 4 != source_total_size) {
    ckb_debug("wrong source size");
    return -99;
  }
  size_t bytes_left = buf_size - (calls_base - buf);
  call_record *calls = (call_record *)malloc(calls_count * sizeof(call_record));
  int ret;
  for (uint32_t i = 0; i < calls_count; i++) {
    ret = call_record_load(calls + i, calls_base + i * 24, bytes_left);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    bytes_left -= 24;
  }

  /* parse run proof part */
  size_t total_size = source_total_size;
  const uint32_t read_values_len = *(uint32_t *)(buf + total_size);
  total_size = total_size + 4 + 64 * read_values_len;
  const uint32_t read_proof_len = *(uint32_t *)(buf + total_size);
  total_size = total_size + 4 + read_proof_len;
  const uint32_t write_values_len = *(uint32_t *)(buf + total_size);
  total_size = total_size + 4 + 32 * write_values_len;
  const uint32_t write_old_proof_len = *(uint32_t *)(buf + total_size);
  total_size = total_size + 4 + write_old_proof_len;

  if (total_size > buf_size) {
    ckb_debug("not enough data to parse run proof");
    return -99;
  }

  program->total_size = total_size;
  program->signature = (uint8_t *)signature;
  program->program_len = program_len;
  program->kind = (evmc_call_kind)call_kind;
  program->flags = flags;
  program->depth = depth;
  program->tx_origin = tx_origin;
  program->sender = sender;
  program->destination = destination;
  program->code_size = code_size;
  program->code_data = (uint8_t *)code_data;
  program->input_size = input_size;
  program->input_data = (uint8_t *)input_data;
  program->return_data_size = return_data_size;
  program->return_data = (uint8_t *)return_data;
  program->beneficiary = beneficiary;
  program->calls_count = calls_count;
  program->call_index = 0;
  program->calls = calls;
  program->next_program = NULL;
  program->prev_program = NULL;
  return 0;
}

void find_contract_info(contract_info **info,
                        contract_info *info_list,
                        size_t info_count,
                        const evmc_address *target) {
  for (size_t info_idx = 0; info_idx < info_count; info_idx++) {
    if (memcmp(info_list[info_idx].address.bytes, target->bytes, 20) == 0) {
      *info = &info_list[info_idx];
      return;
    }
  }
  debug_print_data("can not find contract info", target->bytes, 20);
  return;
}

int contract_info_init(contract_info *info,
                       const uint8_t *witness_buf,
                       size_t witness_size,
                       evmc_address *address) {
  if (witness_size > WITNESS_SIZE) {
    ckb_debug("witness size too large");
    return -99;
  }
  info->witness_buf = (uint8_t *)malloc(witness_size);
  info->witness_size = witness_size;
  memcpy(info->witness_buf, witness_buf, witness_size);
  memcpy(info->address.bytes, address->bytes, 20);
  info->program_index = 0;

  int ret;
  uint8_t zero_u32[4];
  memset(zero_u32, 0, 4);
  uint8_t *buf = info->witness_buf;
  size_t buf_size = witness_size;
  size_t program_count = 0;
  contract_program *head_program = NULL;
  contract_program *prev_program = NULL;
  while (1) {
    contract_program *current_program = (contract_program *)malloc(sizeof(contract_program));
    ret = contract_program_load(current_program, buf, buf_size);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (head_program == NULL) {
      head_program = current_program;
    }
    if (prev_program != NULL) {
      prev_program->next_program = current_program;
    }
    current_program->prev_program = prev_program;
    prev_program = current_program;
    program_count += 1;

    buf += current_program->total_size;
    buf_size -= current_program->total_size;
    if (buf_size == 4) {
      if (memcmp(buf, zero_u32, 4) != 0) {
        ckb_debug("Invalid witness finish data");
        return -99;
      }
      break;
    } else if (buf_size < 4) {
      ckb_debug("invalid witness: not enough buf data");
      return -99;
    }
  }
  if (head_program == NULL) {
    ckb_debug("no program in witness");
    return -99;
  }
  info->code_size = head_program->code_size;
  info->code_data = head_program->code_data;
  info->head_program = head_program;
  info->current_program = head_program;
  info->program_count = program_count;
  info->is_main = false;
  return 0;
}

int contract_info_next_program(contract_info *info) {
  /* Update info to next program:
   * - kind
   * - code_offset (when create)
   * - code_size (when create)
   * - current_program
   * - program_index
   */

  if (info->current_program == NULL) {
    ckb_debug("program reached end");
    return -99;
  }

  contract_program *program = info->current_program;
  if (program->kind == EVMC_CREATE) {
    /* Used in: get_code_size,copy_code */
    info->code_size = program->return_data_size;
    info->code_data = program->return_data;
  }

  if (global_current_is_main) {
    if (program->call_index != program->calls_count) {
      ckb_debug("call count not match");
      return -99;
    }
  }
  info->current_program = program->next_program;
  info->program_index += 1;
  return 0;
}

int contract_info_list_verify_complete(const contract_info *info_list, const size_t info_count) {
  if (global_current_is_main) {
    for (size_t i = 0; i < info_count; i++) {
      const contract_info *info = info_list + i;
      if (info->program_index != info->program_count || info->current_program != NULL) {
        ckb_debug("program not finished");
        return -99;
      }
      contract_program *current_program = info->head_program;
      for (size_t j = 0; j < info->program_count; j++) {
        if (current_program->call_index != current_program->calls_count) {
          ckb_debug("calls finished");
          return -99;
        }
        current_program = current_program->next_program;
      }
    }
  } else {
    /* Check current contract's call_index reach the end */
  }
  return 0;
}

int contract_info_process_calls(contract_info *dest_info,
                                contract_info *info_list,
                                size_t info_count) {
  /* Change:
   *  call_index
   *  Increase all sub-programs' program_index
   */
  contract_program *current_program = dest_info->current_program;
  if (current_program->call_index != 0) {
    ckb_debug("destination program not fresh");
    return -99;
  }

  int ret;
  while (current_program->call_index < current_program->calls_count) {
    call_record call = current_program->calls[current_program->call_index];
    contract_info *info = NULL;
    find_contract_info(&info, info_list, info_count, &call.destination);
    if (info == NULL) {
      ckb_debug("can not find call destination contract");
      return -99;
    }
    if (call.program_index != info->program_index) {
      ckb_debug("program_index not match");
      return -99;
    }
    ret = contract_info_process_calls(info, info_list, info_count);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    current_program->call_index += 1;
  }
  ret = contract_info_next_program(dest_info);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  return 0;
}

int contract_info_reach_program(const contract_info *sender_info,
                                contract_info *dest_info) {
  const contract_program *sender_program = sender_info->current_program;
  const call_record call = sender_program->calls[sender_program->call_index];

  if (call.program_index > dest_info->program_index) {
    ckb_debug("destination contract already passed the program");
    return -99;
  }
  int ret;
  for (size_t i = call.program_index; i < dest_info->program_index; i++) {
    ret = contract_info_next_program(dest_info);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  return 0;
}

int contract_info_call(const contract_info *sender_info,
                       const contract_info *dest_info,
                       const evmc_address *tx_origin,
                       const struct evmc_message *msg,
                       struct evmc_result *res) {
  contract_program *sender_program = sender_info->current_program;
  const contract_program *dest_program = dest_info->current_program;

  /* Check call record */
  const call_record call = sender_program->calls[sender_program->call_index];
  if (memcmp(call.destination.bytes, dest_info->address.bytes, 20) != 0) {
    ckb_debug("call record destination not match");
    return -99;
  }
  if (call.program_index != dest_info->program_index) {
    ckb_debug("call record program_index not match");
    return -99;
  }
  if (dest_program == NULL) {
    ckb_debug("program reach the end");
    return -99;
  }

  /* Check destination program:
   *  - kind
   *  - tx_origin
   *  - sender
   *  - destination
   *  - code_size (when create)
   *  - code_data (when create)
   *  - input_size
   *  - input_data
   *  - witness_offset
   *
   * Fill return data
   */
  if (dest_program->kind != msg->kind) {
    ckb_debug("call kind not match");
    return -99;
  }

  if (memcmp(dest_program->tx_origin.bytes, tx_origin->bytes, 20) != 0) {
    ckb_debug("tx_origin not match");
    return -99;
  }
  if (memcmp(dest_program->sender.bytes, msg->sender.bytes, 20) != 0) {
    ckb_debug("sender not match");
    return -99;
  }

  if (dest_program->kind == EVMC_CREATE) {
    if (dest_info->program_index != 0) {
      ckb_debug("CREATE must be first program");
      return -99;
    }
    if (dest_program->code_size != msg->input_size) {
      ckb_debug("CREATE code size not match");
      return -99;
    }
    if (memcmp(dest_program->code_data, msg->input_data, msg->input_size) != 0) {
      ckb_debug("CREATE code data not match");
    }
    if (dest_program->input_size != 0) {
      ckb_debug("CREATE input size must be zero");
      return -99;
    }
    if (dest_program->input_data != NULL) {
      ckb_debug("CREATE input data must be NULL");
      return -99;
    }
    memcpy(res->create_address.bytes, call.destination.bytes, 20);
  } else {
    if (memcmp(msg->destination.bytes, dest_info->address.bytes, 20) != 0) {
      ckb_debug("destination not match");
      return -99;
    }
    /* call code is checked in it's own script group */
    if (dest_program->input_size == 0) {
      ckb_debug("CALL input size can not be zero");
      return -99;
    }
    if (dest_program->input_size != msg->input_size) {
      ckb_debug("CALL input size not match");
      return -99;
    }
    if (memcmp(dest_program->input_data, msg->input_data, msg->input_size) != 0) {
      ckb_debug("CALL input data not match");
      return -99;
    }
    memset(res->create_address.bytes, 0, 20);
  }
  res->status_code = EVMC_SUCCESS;
  res->gas_left = msg->gas;
  res->output_size = dest_program->return_data_size;
  res->output_data = dest_program->return_data;
  res->release = NULL;
  memset(res->padding, 0, 4);
  sender_program->call_index += 1;
  return 0;
}

struct evmc_host_context {
  csal_change_t *existing_values;
  csal_change_t *changes;
  evmc_address tx_origin;
  /* selfdestruct beneficiary */
  evmc_address beneficiary;
  bool destructed;
};

struct evmc_tx_context get_tx_context(struct evmc_host_context* context) {
  struct evmc_tx_context ctx{};
  ctx.tx_origin = context->tx_origin;
  return ctx;
}

bool account_exists(struct evmc_host_context* context,
                    const evmc_address* address) {
  return true;
}

evmc_bytes32 get_storage(struct evmc_host_context* context,
                         const evmc_address* address,
                         const evmc_bytes32* key) {
  evmc_bytes32 value{};
  int ret;
  ret = csal_change_fetch(context->changes, key->bytes, value.bytes);
  if (ret != 0) {
    ret = csal_change_fetch(context->existing_values, key->bytes, value.bytes);
    if (ret != 0) {
      memset(value.bytes, 0, 32);
    }
  }
  return value;
}

enum evmc_storage_status set_storage(struct evmc_host_context* context,
                                     const evmc_address* address,
                                     const evmc_bytes32* key,
                                     const evmc_bytes32* value) {
  /* int _ret; */
  csal_change_insert(context->changes, key->bytes, value->bytes);
  return EVMC_STORAGE_ADDED;
}

size_t get_code_size(struct evmc_host_context* context,
                     const evmc_address* address) {
  contract_info *info = NULL;
  find_contract_info(&info, global_info_list, global_info_count, address);
  if (info == NULL) {
    debug_print_data("[get_code_size] can not find contract", address->bytes, 20);
    return 0;
  }
  return info->code_size;
}

evmc_bytes32 get_code_hash(struct evmc_host_context* context,
                           const evmc_address* address) {
  evmc_bytes32 hash{};
  return hash;
}

size_t copy_code(struct evmc_host_context* context,
                 const evmc_address* address,
                 size_t code_offset,
                 uint8_t* buffer_data,
                 size_t buffer_size) {
  contract_info *info = NULL;
  find_contract_info(&info, global_info_list, global_info_count, address);
  if (info == NULL) {
    debug_print_data("[copy_code] can not find contract", address->bytes, 20);
    return 0;
  }
  if (info->code_size < code_offset) {
    debug_print_int("invalid code_offset", code_offset);
    debug_print_data("invalid code_offset for", address->bytes, 20);
    return 0;
  }
  size_t done_size = buffer_size;
  if (info->code_size < code_offset +  buffer_size) {
    done_size = info->code_size - code_offset;
  }
  memcpy(buffer_data, info->code_data + code_offset, done_size);
  return done_size;
}

evmc_uint256be get_balance(struct evmc_host_context* context,
                           const evmc_address* address) {
  // TODO: how to return balance?
  evmc_uint256be balance{};
  return balance;
}

void selfdestruct(struct evmc_host_context* context,
                  const evmc_address* address,
                  const evmc_address* beneficiary) {
  memcpy(context->beneficiary.bytes, beneficiary->bytes, 20);
  context->destructed = true;
}

struct evmc_result call(struct evmc_host_context* context,
                        const struct evmc_message* msg) {
  int ret;
  struct evmc_result res{};
  contract_info *sender_info = NULL;
  contract_info *dest_info = NULL;

  find_contract_info(&sender_info, global_info_list, global_info_count, &msg->sender);
  if (sender_info == NULL) {
    res.status_code = EVMC_REVERT;
    return res;
  }

  evmc_address destination{};
  if (msg->kind == EVMC_CREATE) {
    /* TODO: security check */
    contract_program *program = sender_info->current_program;
    call_record call = program->calls[program->call_index];
    memcpy(destination.bytes, call.destination.bytes, 20);
  } else {
    memcpy(destination.bytes, msg->destination.bytes, 20);
  }
  find_contract_info(&dest_info, global_info_list, global_info_count, &destination);
  if (dest_info == NULL) {
    res.status_code = EVMC_REVERT;
    return res;
  }

  if (global_current_is_main) {
    ret = contract_info_call(sender_info, dest_info, &context->tx_origin, msg, &res);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
    ret = contract_info_process_calls(dest_info, global_info_list, global_info_count);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
  } else {
    /* Increase destination contract's program_index fit sender's call record */
    ret = contract_info_reach_program(sender_info, dest_info);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
    ret = contract_info_call(sender_info, dest_info, &context->tx_origin, msg, &res);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
    ret = contract_info_next_program(dest_info);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
  }

  return res;
}

void emit_log(struct evmc_host_context* context,
              const evmc_address* address,
              const uint8_t* data,
              size_t data_size,
              const evmc_bytes32 topics[],
              size_t topics_count) {
  /* Do nothing */
}


inline int verify_params(const uint8_t *signature_data,
                         const uint8_t call_kind,
                         const uint32_t flags,
                         const uint32_t depth,
                         const evmc_address *tx_origin,
                         const evmc_address *sender,
                         const evmc_address *destination,
                         const uint32_t code_size,
                         const uint8_t *code_data,
                         const uint32_t input_size,
                         const uint8_t *input_data) {
  debug_print_data("signature: ", signature_data, 65);
  debug_print_int("kind : ", call_kind);
  debug_print_int("flags: ", flags);
  debug_print_int("depth: ", depth);
  debug_print_data("tx_origin  : ", tx_origin->bytes, 20);
  debug_print_data("sender     : ", sender->bytes, 20);
  debug_print_data("destination: ", destination->bytes, 20);
  debug_print_data("code : ", code_data, code_size);
  debug_print_data("input: ", input_data, input_size);

  int ret;
  uint64_t len;
  blake2b_state blake2b_ctx;
  uint8_t witness_buf[WITNESS_SIZE];
  uint8_t zero_signature[65];
  memset(zero_signature, 0, 65);

  if (!global_touched) {
    ckb_debug("initializing ...");
    /* Load current contract address */
    uint8_t script[SCRIPT_SIZE];
    len = SCRIPT_SIZE;
    ret = ckb_checked_load_script(script, &len, 0);
    if (ret != CKB_SUCCESS) {
      ckb_debug("load current script failed");
      return ret;
    }
    size_t script_size = len;
    mol_seg_t script_seg;
    script_seg.ptr = (uint8_t *)script;
    script_seg.size = script_size;
    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
      return ERROR_INVALID_DATA;
    }
    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
    if (args_bytes_seg.size != CSAL_SCRIPT_ARGS_LEN) {
      return ERROR_INVALID_DATA;
    }
    global_current_contract = *(evmc_address *)args_bytes_seg.ptr;
    debug_print_data("current contract", global_current_contract.bytes, 20);

    /* Load all contract witness in current transaction */
    uint8_t type_script[SCRIPT_SIZE];
    size_t input_index = 0;
    while (1) {
      if (global_info_count >= MAX_CONTRACT_COUNT) {
        ckb_debug("too many contract in one transaction");
        return -100;
      }
      len = SCRIPT_SIZE;
      ret = ckb_load_cell_by_field(type_script, &len, 0, input_index, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE);
      if (ret == CKB_INDEX_OUT_OF_BOUND) {
        ckb_debug("load inputs finised");
        break;
      } else if (ret == CKB_ITEM_MISSING) {
        debug_print_int("ignore input", input_index);
        input_index += 1;
        continue;
      } else if (ret != CKB_SUCCESS) {
        debug_print_int("load type script from input failed", input_index);
        return ret;
      }
      debug_print_int("loaded input", input_index);
      bool code_matched = false;
      ret = check_script_code(script, script_size, type_script, len, &code_matched);
      if (ret != CKB_SUCCESS) {
        debug_print_int("check type script from input failed", input_index);
        return ret;
      }
      if (code_matched) {
        mol_seg_t script_seg;
        script_seg.ptr = type_script;
        script_seg.size = len;
        mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
        mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
        if (args_bytes_seg.size != CSAL_SCRIPT_ARGS_LEN) {
          return ERROR_INVALID_DATA;
        }
        evmc_address tmp_addr = *(evmc_address *)args_bytes_seg.ptr;
        debug_print_data("args_bytes_seg", args_bytes_seg.ptr, 20);
        debug_print_data("tmp_addr", tmp_addr.bytes, 20);
        len = WITNESS_SIZE;
        ret = ckb_load_witness(witness_buf, &len, 0, input_index, CKB_SOURCE_INPUT);
        if (ret != CKB_SUCCESS) {
          debug_print_int("load witness from input failed", input_index);
          return ret;
        }
        mol_seg_t witness_seg;
        witness_seg.ptr = (uint8_t *)witness_buf;
        witness_seg.size = len;
        debug_print_int("load witness:", (int) witness_seg.size);
        if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
          return ERROR_INVALID_DATA;
        }
        mol_seg_t content_seg = MolReader_WitnessArgs_get_input_type(&witness_seg);
        if (MolReader_BytesOpt_is_none(&content_seg)) {
          return ERROR_INVALID_DATA;
        }
        mol_seg_t content_bytes_seg = MolReader_Bytes_raw_bytes(&content_seg);
        debug_print_int("parse input contract info", input_index);
        contract_info *info = global_info_list + global_info_count;
        ret = contract_info_init(info, content_bytes_seg.ptr, content_bytes_seg.size, &tmp_addr);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        debug_print_data("info->address", info->address.bytes, 20);
        ckb_debug("parse input contract info finished");
        global_info_count += 1;
      }
      input_index += 1;
    }

    size_t output_index = 0;
    while (1) {
      if (global_info_count >= MAX_CONTRACT_COUNT) {
        ckb_debug("too many contract in one transaction");
        return -100;
      }
      len = SCRIPT_SIZE;
      ret = ckb_load_cell_by_field(type_script, &len, 0, output_index, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE);
      if (ret == CKB_INDEX_OUT_OF_BOUND) {
        ckb_debug("load outputs finised");
        break;
      } else if (ret == CKB_ITEM_MISSING) {
        debug_print_int("ignore output", output_index);
        output_index += 1;
        continue;
      } else if (ret != CKB_SUCCESS) {
        debug_print_int("load type script from output failed", output_index);
        return ret;
      }
      debug_print_int("loaded output", output_index);
      bool code_matched = false;
      ret = check_script_code(script, script_size, type_script, len, &code_matched);
      if (ret != CKB_SUCCESS) {
        debug_print_int("checkout type script from output failed", output_index);
        return ret;
      }
      if (code_matched) {
        mol_seg_t script_seg;
        script_seg.ptr = type_script;
        script_seg.size = len;
        mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
        mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
        if (args_bytes_seg.size != CSAL_SCRIPT_ARGS_LEN) {
          return ERROR_INVALID_DATA;
        }
        evmc_address tmp_addr = *(evmc_address *)args_bytes_seg.ptr;
        debug_print_data("args_bytes_seg", args_bytes_seg.ptr, 20);
        debug_print_data("tmp_addr", tmp_addr.bytes, 20);
        bool has_input = false;
        for (size_t info_idx = 0; info_idx < global_info_count; info_idx++) {
          if (memcmp(global_info_list[info_idx].address.bytes, tmp_addr.bytes, 20) == 0) {
            has_input = true;
            break;
          }
        }
        if (!has_input) {
          len = WITNESS_SIZE;
          ret = ckb_load_witness(witness_buf, &len, 0, output_index, CKB_SOURCE_OUTPUT);
          if (ret != CKB_SUCCESS) {
            debug_print_int("load witness from output failed", input_index);
            return ret;
          }
          mol_seg_t witness_seg;
          witness_seg.ptr = (uint8_t *)witness_buf;
          witness_seg.size = len;
          debug_print_int("load witness:", (int) witness_seg.size);
          if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
            return ERROR_INVALID_DATA;
          }
          mol_seg_t content_seg = MolReader_WitnessArgs_get_output_type(&witness_seg);
          if (MolReader_BytesOpt_is_none(&content_seg)) {
            return ERROR_INVALID_DATA;
          }
          mol_seg_t content_bytes_seg = MolReader_Bytes_raw_bytes(&content_seg);
          debug_print_int("parse output contract info", output_index);
          contract_info *info = global_info_list + global_info_count;
          ret = contract_info_init(info, content_bytes_seg.ptr, content_bytes_seg.size, &tmp_addr);
          if (ret != CKB_SUCCESS) {
            return ret;
          }
          debug_print_data("info->address", info->address.bytes, 20);
          ckb_debug("parse output contract info finished");
          global_info_count += 1;
        }
      }
      output_index += 1;
    }

    /* Verify:
     *  - there is one and only one non-zero signature
     */
    bool has_entrance_signature = false;
    for (size_t info_idx = 0; info_idx < global_info_count; info_idx++) {
      contract_info *info = &global_info_list[info_idx];
      contract_program *current_program = info->head_program;
      debug_print_int("info_idx", info_idx);
      debug_print_data("info->address", info->address.bytes, 20);
      for (size_t program_idx = 0; program_idx < info->program_count; program_idx++) {
        debug_print_int("program_idx", program_idx);
        debug_print_data("current_program->signature", current_program->signature, 65);
        if (memcmp(current_program->signature, zero_signature, 65) != 0) {
          if (program_idx != 0) {
            ckb_debug("main signature is not in first program");
            return -100;
          }
          if (info->program_count != 1) {
            ckb_debug("main contract only allow 1 program");
            return -100;
          }
          if (has_entrance_signature) {
            ckb_debug("has multiple entrance signature");
            return -100;
          }
          if (memcmp(global_current_contract.bytes, info->address.bytes, 20) == 0) {
            global_current_is_main = true;
          }
          info->is_main = true;
          memcpy(global_tx_origin.bytes, current_program->tx_origin.bytes, 20);
          has_entrance_signature = true;
        }
        current_program = current_program->next_program;
      }
    }
    if (!has_entrance_signature) {
      ckb_debug("no entrance signature found");
      return -100;
    }

    /*
     * - verify code_hash not changed
     * - verify code_hash in data filed match the blake2b_h256(code_data)
     */
    if (call_kind != EVMC_CREATE) {
      uint8_t code_hash[32];
      blake2b_init(&blake2b_ctx, 32);
      blake2b_update(&blake2b_ctx, code_data, code_size);
      blake2b_final(&blake2b_ctx, code_hash, 32);
      debug_print_data("code: ", code_data, code_size);
      debug_print_data("code_hash: ", code_hash, 32);

      uint8_t hash[32];
      len = 32;
      ret = ckb_load_cell_data(hash, &len, 32, 0, CKB_SOURCE_GROUP_INPUT);
      if (ret != CKB_SUCCESS) {
        ckb_debug("load cell data from input failed");
        return ret;
      }
      if (len != 32) {
        return -100;
      }
      debug_print_data("input code hash: ", hash, 32);
      if (memcmp(code_hash, hash, 32) != 0) {
        return -101;
      }

      len = 32;
      ret = ckb_load_cell_data(hash, &len, 32, 0, CKB_SOURCE_GROUP_OUTPUT);
      if (ret == CKB_SUCCESS) {
        ckb_debug("load cell data from output failed");
        if (len != 32) {
          return -102;
        }
        debug_print_data("output code hash: ", hash, 32);
        if (memcmp(code_hash, hash, 32) != 0) {
          return -103;
        }
      } else if (ret != CKB_INDEX_OUT_OF_BOUND) {
        return ret;
      }
    }
  }

  /* Verify sender by signature field */
  if (global_current_is_main) {
    ckb_debug("Verify EoA sender signature");
    uint8_t tx_hash[32];
    len = 32;
    ret = ckb_load_tx_hash(tx_hash, &len, 0);
    if (ret != CKB_SUCCESS) {
      ckb_debug("load tx hash failed");
      return ret;
    }
    blake2b_init(&blake2b_ctx, 32);
    blake2b_update(&blake2b_ctx, tx_hash, 32);

    for (size_t info_idx = 0; info_idx < global_info_count; info_idx++) {
      contract_info *info = &global_info_list[info_idx];
      memcpy(witness_buf, info->witness_buf, info->witness_size);
      if (info->is_main) {
        memset(witness_buf + 4, 0, 65);
      }
      blake2b_update(&blake2b_ctx, witness_buf, info->witness_size);
    }

    // Verify EoA account call contract
    uint8_t sign_message[32];
    blake2b_final(&blake2b_ctx, sign_message, 32);

    /* Load signature */
    secp256k1_context context;
    uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
    ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
    if (ret != 0) {
      debug_print_int("ckb_secp256k1_custom_verify_only_initialize", ret);
      return ret;
    }

    int recid = (int)signature_data[64];
    secp256k1_ecdsa_recoverable_signature signature;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(&context, &signature, signature_data, recid) == 0) {
      return -92;
    }

    /* Recover pubkey */
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, sign_message) != 1) {
      return -93;
    }

    /* Check pubkey hash */
    uint8_t temp[65];
    size_t pubkey_size = 33;
    if (secp256k1_ec_pubkey_serialize(&context, temp,
                                      &pubkey_size, &pubkey,
                                      SECP256K1_EC_COMPRESSED) != 1) {
      return -94;
    }
    blake2b_init(&blake2b_ctx, 32);
    blake2b_update(&blake2b_ctx, temp, pubkey_size);
    blake2b_final(&blake2b_ctx, temp, 32);

    /* Verify entrance program sender */
    if (memcmp(sender->bytes, temp, 20) != 0) {
      ckb_debug("EoA sender not match the signature");
      return -95;
    }
    /* Verify tx_origin */
    if (memcmp(sender->bytes, tx_origin->bytes, 20) != 0) {
      ckb_debug("Sender is not tx_origin");
      return -96;
    }
  } else {
    bool found_sender_contract = false;
    for (size_t info_idx = 0; info_idx < global_info_count; info_idx++) {
      contract_info *info = &global_info_list[info_idx];
      if (memcmp(info->address.bytes, sender->bytes, 20) == 0) {
        found_sender_contract = true;
        break;
      }
    }
    if (!found_sender_contract) {
      ckb_debug("Can not found sender contract in sub contract");
      return -100;
    }
  }

  /* Verify tx_origin all the same */
  if (memcmp(global_tx_origin.bytes, tx_origin->bytes, 20) != 0) {
    /* tx_origin not the same */
    return -97;
  }

  /* Verify destination match current script args */
  if (memcmp(destination->bytes, global_current_contract.bytes, CSAL_SCRIPT_ARGS_LEN) != 0) {
    ckb_debug("ERROR: destination not match current script args");
    return -98;
  }


  if (!global_touched) {
    global_touched = true;
  }
  return 0;
}

inline void context_init(struct evmc_host_context* context,
                         struct evmc_vm *_vm,
                         struct evmc_host_interface *_interface,
                         evmc_address tx_origin,
                         csal_change_t *existing_values,
                         csal_change_t *changes) {
  context->existing_values = existing_values;
  context->changes = changes;
  context->tx_origin = tx_origin;
  context->destructed = false;
  memset(context->beneficiary.bytes, 0, 20);
}

inline void return_result(const struct evmc_message *_msg, const struct evmc_result *res) {
  /* Do nothing */
}

inline int verify_result(struct evmc_host_context* context,
                         const struct evmc_message *msg,
                         const struct evmc_result *res,
                         const uint8_t *return_data,
                         const size_t return_data_size,
                         const evmc_address *beneficiary) {
  int ret;
  if (msg->kind == EVMC_CREATE) {
    /*
     * verify code_hash in output data filed match the blake2b_h256(res.output_data)
     */
    uint8_t code_hash[32];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, 32);
    blake2b_update(&blake2b_ctx, res->output_data, res->output_size);
    blake2b_final(&blake2b_ctx, code_hash, 32);
    debug_print_data("code: ", res->output_data, res->output_size);
    debug_print_data("code_hash: ", code_hash, 32);

    uint8_t hash[32];
    uint64_t len = 32;
    ret = ckb_load_cell_data(hash, &len, 32, 0, CKB_SOURCE_GROUP_OUTPUT);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 32) {
      return -110;
    }
    debug_print_data("output code hash: ", hash, 32);
    if (memcmp(code_hash, hash, 32) != 0) {
      return -111;
    }
  }

  /* Verify return data */
  if (return_data_size != res->output_size) {
    return -112;
  }
  if (memcmp(return_data, res->output_data, return_data_size) != 0) {
    return -113;
  }
  /* verify selfdestruct */
  if (memcmp(beneficiary->bytes, context->beneficiary.bytes, 20) != 0) {
    return -114;
  }

  contract_info *info = NULL;
  find_contract_info(&info, global_info_list, global_info_count, &global_current_contract);
  if (info == NULL) {
    ckb_debug("can not found contract info");
    return -111;
  }
  /* Verify res.output_data match the program.return_data */
  if (res->output_size != info->current_program->return_data_size) {
    ckb_debug("return data size not match");
    return -111;
  }
  debug_print_data("output_data", res->output_data, res->output_size);
  debug_print_data("return_data", info->current_program->return_data, res->output_size);
  if (memcmp(res->output_data, info->current_program->return_data, res->output_size) != 0) {
    ckb_debug("return data not match");
    return -111;
  }

  ret = contract_info_next_program(info);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (info->program_index == info->program_count) {
    ret = contract_info_list_verify_complete(global_info_list, global_info_count);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  return 0;
}
