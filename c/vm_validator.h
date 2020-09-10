#include <evmc/evmc.h>
#include <intx/intx.hpp>
#include <merkle_tree.h>

#define CSAL_VALIDATOR_TYPE 1
#include "validator.h"
#include "secp256k1_helper.h"

#define ONE_CKB ((uint64_t)100000000)
#define MIN_CONTRACT_CAPACITY ((uint64_t)(ONE_CKB * (uint64_t)158))

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

int check_eoa_script(blake2b_state *blake2b_ctx,
                     uint8_t *type_script,
                     const size_t type_script_size,
                     uint8_t *lock_script,
                     const size_t lock_script_size,
                     bool *matched,
                     evmc_address *address,
                     mol_seg_t *lock_args_bytes_seg,
                     mol_seg_t *type_args_bytes_seg) {
  mol_seg_t type_script_seg;
  type_script_seg.ptr = type_script;
  type_script_seg.size = type_script_size;
  if (MolReader_Script_verify(&type_script_seg, false) != MOL_OK) {
    return ERROR_INVALID_DATA;
  }
  static uint8_t type_id_code_hash[32]
    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x44};
  mol_seg_t type_code_hash_seg = MolReader_Script_get_code_hash(&type_script_seg);
  if (memcmp(type_code_hash_seg.ptr, type_id_code_hash, 32) != 0) {
    *matched = false;
    return 0;
  }

  mol_seg_t lock_script_seg;
  lock_script_seg.ptr = lock_script;
  lock_script_seg.size = lock_script_size;
  if (MolReader_Script_verify(&lock_script_seg, false) != MOL_OK) {
    return ERROR_INVALID_DATA;
  }
  /* FIXME: hard-coded */
  static uint8_t anyone_can_pay_code_hash[32]
    /* commit-id: d06f81ab40ddab7236aea4a1d993b050d3f7296a */
    = {0x8b, 0x10, 0x14, 0x4d, 0xaa, 0x11, 0x01, 0x52,
       0xe7, 0x8d, 0xd0, 0x02, 0xb4, 0x4f, 0x42, 0x92,
       0x38, 0xcb, 0xbe, 0xe5, 0xe6, 0x20, 0x52, 0x20,
       0x5f, 0xdc, 0x6a, 0x1f, 0xc2, 0xc5, 0x7a, 0x2a};
    /* commit-id: deac6801a95596d74e2da8f2f1a6727309d36100 */
    /* = {0x0f, 0xb3, 0x43, 0x95, 0x3e, 0xe7, 0x8c, 0x99, */
    /*    0x86, 0xb0, 0x91, 0xde, 0xfb, 0x62, 0x52, 0x15, */
    /*    0x4e, 0x0b, 0xb5, 0x10, 0x44, 0xfd, 0x28, 0x79, */
    /*    0xfd, 0xe5, 0xb2, 0x73, 0x14, 0x50, 0x61, 0x11}; */
  mol_seg_t lock_code_hash_seg = MolReader_Script_get_code_hash(&lock_script_seg);
  if (memcmp(lock_code_hash_seg.ptr, anyone_can_pay_code_hash, 32) != 0) {
    *matched = false;
    return 0;
  }

  mol_seg_t type_args_seg = MolReader_Script_get_args(&type_script_seg);
  *type_args_bytes_seg = MolReader_Bytes_raw_bytes(&type_args_seg);
  mol_seg_t lock_args_seg = MolReader_Script_get_args(&lock_script_seg);
  *lock_args_bytes_seg = MolReader_Bytes_raw_bytes(&lock_args_seg);
  if (type_args_bytes_seg->size != 32) {
    debug_print_int("Invalid type script args length", type_args_bytes_seg->size);
    return -99;
  }
  if (lock_args_bytes_seg->size != 20) {
    debug_print_int("Invalid lock script args length", lock_args_bytes_seg->size);
    return -99;
  }
  uint8_t buf[32];
  blake2b_init(blake2b_ctx, 32);
  blake2b_update(blake2b_ctx, type_args_bytes_seg->ptr, type_args_bytes_seg->size);
  blake2b_update(blake2b_ctx, lock_args_bytes_seg->ptr, lock_args_bytes_seg->size);
  blake2b_final(blake2b_ctx, buf, 32);
  memcpy(address->bytes, buf, 20);

  *matched = true;
  return 0;
}

uint64_t script_occupied_capacity(uint8_t* script, uint64_t size) {
  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = size;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_INVALID_DATA;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  return args_bytes_seg.size + 32 + 1;
}

evmc_uint256be compact_to_difficulty(uint32_t compact) {
  uint32_t exponent = compact >> 24;
  intx::uint256 mantissa = compact & 0x00ffffff;

  intx::uint256 target = 0;
  if (exponent <= 3) {
    mantissa >>= 8 * (3 - exponent);
    target = mantissa;
  } else {
    target = mantissa;
    target <<= 8 * (exponent - 3);
  }

  bool overflow = !(mantissa == 0) && (exponent > 32);

  intx::uint256 difficulty = 0;
  if (target == 0 || overflow) {
    difficulty = 0;
  } else if (target == 1) {
    difficulty = ~intx::uint256{0};
  } else {
    intx::uint512 hspace = 1;
    hspace = hspace << 256;
    intx::uint512 htarget = target;
    difficulty = (hspace / htarget).lo;
  }
  evmc_uint256be ret;
  intx::be::store(ret.bytes, difficulty);
  return ret;
}

cbmt_node node_merge(void *merge_ctx,
                     cbmt_node *left,
                     cbmt_node *right) {
  cbmt_node ret;
  blake2b_state *blake2b_ctx = (blake2b_state *)merge_ctx;
  blake2b_init(blake2b_ctx, CBMT_NODE_SIZE);
  blake2b_update(blake2b_ctx, left->bytes, CBMT_NODE_SIZE);
  blake2b_update(blake2b_ctx, right->bytes, CBMT_NODE_SIZE);
  blake2b_final(blake2b_ctx, ret.bytes, CBMT_NODE_SIZE);
  return ret;
}

#define MAX_CONTRACT_COUNT 64
#define MAX_EOA_COUNT 1024
#define MAX_HEADER_COUNT 128
#define HEADER_SIZE 4096

typedef struct {
  evmc_address destination;
  size_t program_index;
  uint64_t value;
  bool transfer_only;
  bool is_eoa;
} call_record;

typedef struct {
  evmc_bytes32 witnesses_root;
  evmc_bytes32 raw_transactions_root;
  size_t proof_lemmas_count;
  evmc_bytes32 *proof_lemmas;
  uint32_t proof_index;
  uint32_t raw_cellbase_tx_size;
  uint8_t *raw_cellbase_tx;
} tx_coinbase;

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
  /* selfdestruct target */
  evmc_address beneficiary;
  uint64_t beneficiary_amount;
  size_t calls_count;
  size_t call_index;
  call_record *calls;
  tx_coinbase *coinbase;
  struct contract_program *next_program;
  struct contract_program *prev_program;
  bool is_processed;
} contract_program;

typedef struct {
  bool is_main;
  bool is_create;
  evmc_address address;
  uint8_t *witness_buf;
  size_t witness_size;
  /* if CREATE, update this field after first call */
  uint8_t *code_data;
  size_t code_size;
  uint64_t input_capacity;
  uint64_t input_balance;
  uint64_t output_capacity;
  uint64_t output_balance;
  /* Variable */
  contract_program *head_program;
  contract_program *current_program;
  size_t special_call_total_count;
  size_t special_call_count;
  size_t program_count;
  size_t program_index;
} contract_info;

typedef struct {
  /* block number */
  uint64_t number;
  /* block hash */
  evmc_bytes32 hash;
  /* Transactions root hash */
  evmc_bytes32 transactions_root;
} header_info;

typedef struct {
  evmc_address address;
  uint8_t type_args[32];
  uint8_t lock_args[20];
  /* -1 for not exists in input */
  int input_index;
  uint64_t input_balance;
  uint64_t input_capacity;
  /* -1 for not exists in output */
  int output_index;
  uint64_t output_balance;
  uint64_t output_capacity;
  /* check if the eoa account balance is changed */
  bool is_used;
} eoa_account;

static bool global_touched = false;
static contract_info global_info_list[MAX_CONTRACT_COUNT];
static size_t global_info_count = 0;
static eoa_account global_eoa_list[MAX_EOA_COUNT];
static size_t global_eoa_count = 0;
static evmc_address global_current_contract;
static bool global_current_is_main = false;
static struct evmc_tx_context global_tx_context;
static header_info global_header_infos[MAX_HEADER_COUNT];
static size_t global_header_count = 0;
static uint64_t global_max_block_number = 0;

int call_record_load(call_record *record, const uint8_t *buf, const size_t buf_size) {
  if (buf_size < (20 + 4 + 8 + 1 + 1)) {
    debug_print("not enough data to parse call_record");
    return -99;
  }

  size_t offset = 0;
  record->destination = *(evmc_address *)(buf + offset);
  offset += 20;
  uint32_t index = *(uint32_t *)(buf + offset);
  record->program_index = (size_t)index;
  offset += 4;
  record->value = *(uint64_t *)(buf + offset);
  offset += 8;
  uint8_t transfer_only = buf[offset];
  if (transfer_only != 1 && transfer_only != 0) {
    debug_print_int("invalid transfer_only value", transfer_only);
    return -99;
  }
  record->transfer_only = transfer_only == 1;
  offset += 1;
  uint8_t is_eoa = buf[offset];
  if (is_eoa != 1 && is_eoa != 0) {
    debug_print_int("invalid is_eoa value", is_eoa);
    return -99;
  }
  record->is_eoa = is_eoa == 1;
  offset += 1;
  if (!record->transfer_only && record->is_eoa) {
    debug_print("is_eoa=true only valid when transfer only");
    return -99;
  }
  debug_print_data("[call.destination]", record->destination.bytes, 20);
  debug_print_int("[call.program_index]", record->program_index);
  debug_print_int("[call.value]", record->value);
  debug_print_int("[call.transfer_only]", record->transfer_only);
  debug_print_int("[call.is_eoa]", record->is_eoa);
  return 0;
}

int verify_call_value(call_record *call, const evmc_message *msg) {
  intx::uint256 value = call->value;
  uint8_t value_bytes[32];
  intx::be::store(value_bytes, value);
  if (memcmp(value_bytes, msg->value.bytes, 32) != 0) {
    debug_print("[ERROR]: value not match");
    debug_print_int("call->value", call->value);
    debug_print_data("value_bytes", value_bytes, 32);
    debug_print_data("msg->value", msg->value.bytes, 32);
    return -99;
  }
  return 0;
}

int tx_coinbase_load(tx_coinbase *coinbase, const uint8_t *buf, const size_t buf_size) {
  size_t offset = 0;
  const evmc_bytes32 witnesses_root = *(evmc_bytes32 *)(buf + offset);
  offset += 32;
  const evmc_bytes32 raw_transactions_root = *(evmc_bytes32 *)(buf + offset);
  offset += 32;
  const uint32_t proof_lemmas_count = *(uint32_t *)(buf + offset);
  offset += 4;
  evmc_bytes32 *proof_lemmas = (evmc_bytes32 *)malloc(sizeof(evmc_bytes32) * proof_lemmas_count);
  for (size_t i = 0; i < proof_lemmas_count; i++) {
    *(proof_lemmas + i) = *(evmc_bytes32 *)(buf + offset);
    offset += 32;
  }
  const uint32_t proof_index = *(uint32_t *)(buf + offset);
  offset += 4;
  const uint32_t raw_cellbase_tx_size = *(uint32_t *)(buf + offset);
  offset += 4;
  uint8_t *raw_cellbase_tx = (uint8_t *)buf + offset;
  offset += raw_cellbase_tx_size;
  if (offset != buf_size) {
    debug_print_int("proof_lemmas_count", proof_lemmas_count);
    debug_print_int("raw_cellbase_tx_size", raw_cellbase_tx_size);
    debug_print_int("offset", offset);
    debug_print_int("buf_size", buf_size);
    debug_print_int("tx_coinbase used size not match, delta", ((int)offset - (int)buf_size));
    return -99;
  }

  coinbase->witnesses_root = witnesses_root;
  coinbase->raw_transactions_root = raw_transactions_root;
  coinbase->proof_lemmas_count = proof_lemmas_count;
  coinbase->proof_lemmas = proof_lemmas;
  coinbase->proof_index = proof_index;
  coinbase->raw_cellbase_tx_size = raw_cellbase_tx_size;
  coinbase->raw_cellbase_tx = raw_cellbase_tx;
  return 0;
}

int contract_program_load(contract_program *program, const uint8_t *buf, const size_t buf_size) {
  const uint32_t source_size = *(uint32_t *)buf;
  if (source_size > buf_size) {
    debug_print("not enough data to parse program");
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
  const uint64_t beneficiary_amount = *(uint64_t *)(return_data + return_data_size + 20);
  /* calls */
  const uint32_t calls_count = *(uint32_t *)(return_data + return_data_size + 20 + 8);
  const uint8_t *calls_base = return_data + return_data_size + 20 + 8 + 4;
  size_t bytes_left = buf_size - (calls_base - buf);
  static size_t call_record_size = 20 + 4 + 8 + 1 + 1;
  call_record *calls = (call_record *)malloc(calls_count * sizeof(call_record));
  int ret;
  for (uint32_t i = 0; i < calls_count; i++) {
    ret = call_record_load(calls + i, calls_base + i * call_record_size, bytes_left);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    bytes_left -= call_record_size;
  }
  const size_t calls_size = calls_count * call_record_size;
  /* coinbase */
  const uint32_t coinbase_size = *(uint32_t *)(calls_base + calls_size);
  tx_coinbase *coinbase = coinbase_size > 0 ? (tx_coinbase *)malloc(sizeof(tx_coinbase)) : NULL;
  if (coinbase_size > 0) {
    const uint8_t *coinbase_base = (uint8_t *)calls_base + calls_size + 4;
    ret = tx_coinbase_load(coinbase, coinbase_base, coinbase_size);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  const size_t source_total_size = calls_base - buf + calls_size + 4 + coinbase_size;
  if (source_total_size > buf_size) {
    debug_print("not enough data to parse program");
    return -99;
  }
  if (source_size + 4 != source_total_size) {
    debug_print_int("source_size", source_size);
    debug_print_int("source_total_size", source_total_size);
    debug_print("wrong source size");
    return -99;
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
    debug_print("not enough data to parse run proof");
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
  program->beneficiary_amount = beneficiary_amount;
  program->calls_count = calls_count;
  program->call_index = 0;
  program->calls = calls;
  program->coinbase = coinbase;
  program->next_program = NULL;
  program->prev_program = NULL;
  program->is_processed = false;
  return 0;
}

void find_eoa_account(eoa_account **account,
                      eoa_account *eoa_list,
                      size_t eoa_count,
                      const evmc_address *target) {
  for (size_t idx = 0; idx < eoa_count; idx++) {
    if (memcmp(eoa_list[idx].address.bytes, target->bytes, 20) == 0) {
      *account = &eoa_list[idx];
      return;
    }
  }
  debug_print_data("can not find eoa account", target->bytes, 20);
  return;
}

void eoa_account_init(eoa_account *account,
                      evmc_address *address,
                      mol_seg_t *type_args,
                      mol_seg_t *lock_args,
                      uint64_t input_balance,
                      uint64_t input_capacity,
                      int input_index) {
  account->is_used = false;
  account->address = *address;
  memcpy(account->type_args, type_args->ptr, type_args->size);
  memcpy(account->lock_args, lock_args->ptr, lock_args->size);
  account->input_balance = input_balance;
  account->input_capacity = input_capacity;
  account->input_index = input_index;
  account->output_index = -1;
  return;
}

void eoa_account_add_balance(eoa_account *account, uint64_t value) {
  debug_print_data("add balance to eoa account", account->address.bytes, 20);
  debug_print_int("add value", value);
  account->is_used = true;
  account->input_balance += value;
  account->input_capacity += value;
}

int eoa_account_sub_balance(eoa_account *account, uint64_t value) {
  debug_print_data("sub balance from eoa account", account->address.bytes, 20);
  debug_print_int("sub value", value);
  if (account->input_balance < value) {
    debug_print_int("eoa account balance not enough, current", account->input_balance);
    debug_print_int("eoa account balance not enough, sub", value);
    return -109;
  }
  account->is_used = true;
  account->input_balance -= value;
  account->input_capacity -= value;
  return 0;
}

int verify_eoa_account(const eoa_account *account) {
  if (account->output_index < 0) {
    debug_print_int("invalid eoa account output index", account->output_index);
    return -109;
  }
  if (memcmp(account->address.bytes, global_tx_context.tx_origin.bytes, 20) == 0) {
    if (account->input_balance < account->output_balance) {
      debug_print_int("tx_origin balance not match, input:", account->input_balance);
      debug_print_int("tx_origin balance not match, output:", account->output_balance);
      return -109;
    }
    if (account->input_capacity < account->output_capacity) {
      debug_print_int("tx_origin capacity not match, input:", account->input_capacity);
      debug_print_int("tx_origin capacity not match, output:", account->output_capacity);
      return -109;
    }

    uint64_t tx_fee = account->input_capacity - account->output_capacity;
    if (tx_fee > ONE_CKB) {
      /* Remove this later */
      debug_print_int("[WARN]: too much transaction fee", tx_fee);
    }
  } else {
    if (!account->is_used) {
      debug_print_data("eoa account is unused", account->address.bytes, 20);
      return -109;
    }
    if (account->input_balance != account->output_balance) {
      debug_print_int("eoa balance not match, input:", account->input_balance);
      debug_print_int("eoa balance not match, output:", account->output_balance);
      return -109;
    }
    if (account->input_capacity != account->output_capacity) {
      debug_print_int("eoa capacity not match, input:", account->input_capacity);
      debug_print_int("eoa capacity not match, output:", account->output_capacity);
      return -109;
    }
  }
  return 0;
}

int eoa_account_list_verify_complete(const eoa_account *eoa_list, const size_t eoa_count) {
  if (global_current_is_main) {
    int ret;
    for (size_t i = 0; i < eoa_count; i++) {
      const eoa_account *account = eoa_list + i;
      ret = verify_eoa_account(account);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  }
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
    debug_print("witness size too large");
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
  size_t special_call_total_count = 0;
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
    if (is_special_call(current_program->kind)) {
      special_call_total_count += 1;
    }
    program_count += 1;

    buf += current_program->total_size;
    buf_size -= current_program->total_size;
    if (buf_size == 4) {
      if (memcmp(buf, zero_u32, 4) != 0) {
        debug_print("Invalid witness finish data");
        return -99;
      }
      break;
    } else if (buf_size < 4) {
      debug_print("invalid witness: not enough buf data");
      return -99;
    }
  }
  if (head_program == NULL) {
    debug_print("no program in witness");
    return -99;
  }
  info->code_size = head_program->code_size;
  info->code_data = head_program->code_data;
  info->head_program = head_program;
  info->current_program = head_program;
  info->special_call_total_count = special_call_total_count;
  info->program_count = program_count;
  info->is_main = false;
  info->is_create = false;
  info->input_balance = 0;
  info->input_capacity = 0;
  info->output_balance = 0;
  info->output_capacity = 0;
  return 0;
}

void contract_info_add_balance(contract_info *info, uint64_t value) {
  debug_print_data("add balance to contract account", info->address.bytes, 20);
  debug_print_int("add value", value);
  info->input_balance += value;
  info->input_capacity += value;
}

int contract_info_sub_balance(contract_info *info, uint64_t value) {
  debug_print_data("sub balance from contract account", info->address.bytes, 20);
  debug_print_int("sub value", value);
  if (info->input_balance < value) {
    debug_print("[ERROR]: balance not enough");
    debug_print_data("info.address", info->address.bytes, 20);
    debug_print_int("info.balance", info->input_balance);
    debug_print_int("value", value);
    return -99;
  }
  info->input_balance -= value;
  info->input_capacity -= value;
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
  debug_print_data(">> next program", info->address.bytes, 20);
  debug_print_int(">> current_program", (long int)info->current_program);
  debug_print_int(">> program_index", info->program_index);
  debug_print_int(">> program_count", info->program_count);

  if (info->current_program == NULL) {
    debug_print("program reached end");
    return -99;
  }

  contract_program *program = info->current_program;
  if (is_create(program->kind)) {
    /* Used in: get_code_size,copy_code */
    info->code_size = program->return_data_size;
    info->code_data = program->return_data;
  }

  if (global_current_is_main) {
    if (program->call_index != program->calls_count) {
      debug_print_int("program->call_index", program->call_index);
      debug_print_int("program->calls_count", program->calls_count);
      debug_print("sub program calls not finished");
      return -99;
    }

    if (!program->is_processed) {
      evmc_address zero_address{};
      memset(zero_address.bytes, 0, 20);
      if (memcmp(program->beneficiary.bytes, zero_address.bytes, 20) != 0) {
        if (program->beneficiary_amount != info->input_capacity) {
          debug_print("beneficiary amount not match");
          debug_print_int("program->beneficiary_amount", program->beneficiary_amount);
          debug_print_int("info->input_capacity", info->input_capacity);
          debug_print_data("info->address", info->address.bytes, 20);
          return -99;
        }
        contract_info *beneficiary_info = NULL;
        find_contract_info(&beneficiary_info, global_info_list, global_info_count, &program->beneficiary);
        if (beneficiary_info == NULL) {
          eoa_account *beneficiary_account = NULL;
          find_eoa_account(&beneficiary_account, global_eoa_list, global_eoa_count, &program->beneficiary);
          if (beneficiary_account == NULL) {
            debug_print_data("can not find selfdestruct target", program->beneficiary.bytes, 20);
            return -99;
          }
          debug_print("add beneficiary to eoa");
          eoa_account_add_balance(beneficiary_account, info->input_capacity);
        } else {
          debug_print("add beneficiary to contract");
          contract_info_add_balance(beneficiary_info, info->input_capacity);
        }
        info->input_balance = 0;
        info->input_capacity = 0;
      }
    }
  }
  program->is_processed = true;
  info->current_program = program->next_program;
  info->program_index += 1;
  return 0;
}

int contract_info_process_calls(contract_info *dest_info,
                                contract_info *info_list,
                                size_t info_count,
                                eoa_account *eoa_list,
                                size_t eoa_count) {
  /* [Change]:
   *  Increase all destination sub-programs' call_index
   *  Increase all destination sub-contracts' program_index
   */
  contract_program *current_program = dest_info->current_program;
  if (current_program->call_index != 0) {
    debug_print("destination program not fresh");
    return -99;
  }

  int ret;
  while (current_program->call_index < current_program->calls_count) {
    call_record call = current_program->calls[current_program->call_index];
    contract_info *info = NULL;
    find_contract_info(&info, info_list, info_count, &call.destination);
    if (call.value > 0) {
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
    if (info != NULL) {
      if (call.value > 0) {
        contract_info_add_balance(info, call.value);
      }
      if (call.program_index != info->program_index) {
        debug_print_int("call.program_index", call.program_index);
        debug_print_int("info->program_index", info->program_index);
        debug_print("program_index not match");
        return -99;
      }
      ret = contract_info_process_calls(info, info_list, info_count, eoa_list, eoa_count);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    } else {
      if (!call.transfer_only) {
        debug_print("call.transfer_only is false");
        return -99;
      }
      if (!call.is_eoa) {
        debug_print("call.is_eoa is false");
        return -99;
      }
      if (call.value == 0) {
        debug_print("call.value == 0");
        return -99;
      }
      /* value transfer */
      eoa_account *account = NULL;
      find_eoa_account(&account, eoa_list, eoa_count, &call.destination);
      if (account == NULL) {
        debug_print("can not find call destination contract/account");
        return -99;
      }
      if (call.value > 0) {
        eoa_account_add_balance(account, call.value);
      }
    }
    current_program->call_index += 1;
  }

  debug_print("[contract_info_next_program] contract_info_process_calls");
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

  if (dest_info->program_index > call.program_index) {
    debug_print_int("call.program_index", call.program_index);
    debug_print_int("dest_info->program_index", dest_info->program_index);
    debug_print("destination contract already passed the program");
    return -99;
  }
  int ret;
  for (size_t i = dest_info->program_index; i < call.program_index; i++) {
    debug_print("[contract_info_next_program] contract_info_reach_program");
    ret = contract_info_next_program(dest_info);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  return 0;
}

/* Increase sender contract current program's call_index */
int contract_info_call(const contract_info *sender_info,
                       const contract_info *dest_info,
                       const evmc_address *tx_origin,
                       const struct evmc_message *msg,
                       struct evmc_result *res) {
  /* [Change]:
   *   1. Set evm_result
   *   2. Increase sender contract.current_program.call_index
   */
  contract_program *sender_program = sender_info->current_program;
  const contract_program *dest_program = dest_info->current_program;

  /* Check call record */
  const call_record call = sender_program->calls[sender_program->call_index];
  if (memcmp(call.destination.bytes, dest_info->address.bytes, 20) != 0) {
    debug_print_data("call.destination", call.destination.bytes, 20);
    debug_print_data("dest_info->address", dest_info->address.bytes, 20);
    debug_print("call record destination not match");
    return -99;
  }
  if (call.program_index != dest_info->program_index) {
    debug_print_int("call.program_index", call.program_index);
    debug_print_int("dest_info.program_index", dest_info->program_index);
    debug_print("call record program_index not match");
    return -99;
  }
  if (dest_program == NULL) {
    debug_print("program reach the end");
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
    debug_print("call kind not match");
    return -99;
  }

  if (memcmp(dest_program->tx_origin.bytes, tx_origin->bytes, 20) != 0) {
    debug_print("tx_origin not match");
    return -99;
  }
  if (memcmp(dest_program->sender.bytes, msg->sender.bytes, 20) != 0) {
    debug_print("sender not match");
    return -99;
  }

  if (is_create(dest_program->kind)) {
    if (dest_info->program_index != 0) {
      debug_print("CREATE must be first program");
      return -99;
    }
    if (dest_program->code_size != msg->input_size) {
      debug_print("CREATE code size not match");
      return -99;
    }
    if (memcmp(dest_program->code_data, msg->input_data, msg->input_size) != 0) {
      debug_print("CREATE code data not match");
    }
    if (dest_program->input_size != 0) {
      debug_print("CREATE input size must be zero");
      return -99;
    }
    if (dest_program->input_data != NULL) {
      debug_print("CREATE input data must be NULL");
      return -99;
    }
    memcpy(res->create_address.bytes, call.destination.bytes, 20);
  } else {
    if (memcmp(msg->destination.bytes, dest_info->address.bytes, 20) != 0) {
      debug_print("destination not match");
      return -99;
    }
    /* call code is checked in it's own script group */
    if (dest_program->input_size == 0) {
      evmc_uint256be zero_value = evmc_uint256be{};
      if (memcmp(zero_value.bytes, msg->value.bytes, 32) == 0) {
        debug_print("CALL input size can not be zero");
        return -99;
      }
    }
    if (dest_program->input_size != msg->input_size) {
      debug_print("CALL input size not match");
      return -99;
    }
    if (memcmp(dest_program->input_data, msg->input_data, msg->input_size) != 0) {
      debug_print("CALL input data not match");
      return -99;
    }
    memset(res->create_address.bytes, 0, 20);
  }
  res->status_code = EVMC_SUCCESS;
  res->gas_left = msg->gas;
  if (is_special_call(msg->kind)) {
    res->output_size = sender_program->return_data_size;
    res->output_data = sender_program->return_data;
  } else {
    res->output_size = dest_program->return_data_size;
    res->output_data = dest_program->return_data;
  }
  res->release = NULL;
  memset(res->padding, 0, 4);
  sender_program->call_index += 1;
  return 0;
}

struct evmc_host_context {
  struct evmc_host_interface *interface;
  csal_change_t *existing_values;
  csal_change_t *changes;
  /* selfdestruct beneficiary */
  evmc_address beneficiary;
  bool destructed;
  int callback_errno;
};

int contract_info_list_verify_complete(const contract_info *info_list, const size_t info_count) {
  if (global_current_is_main) {
    for (size_t i = 0; i < info_count; i++) {
      const contract_info *info = info_list + i;
      if (info->program_index != info->program_count || info->current_program != NULL) {
        debug_print_data("address", info->address.bytes, 20);
        debug_print_int("program_index", info->program_index);
        debug_print_int("program_count", info->program_count);
        debug_print("program not finished");
        return -99;
      }
      contract_program *current_program = info->head_program;
      for (size_t j = 0; j < info->program_count; j++) {
        if (current_program->call_index != current_program->calls_count) {
          debug_print("calls finished");
          return -99;
        }
        current_program = current_program->next_program;
      }
      if (info->input_balance != info->output_balance) {
        debug_print_int("contract balance not match, input:", info->input_balance);
        debug_print_int("contract balance not match, output:", info->output_balance);
        return -99;
      }
      if (info->input_capacity != info->output_capacity
          && !(info->is_create
               && (info->output_capacity - info->input_capacity) == MIN_CONTRACT_CAPACITY)) {
        debug_print_int("contract capacity not match, input:", info->input_capacity);
        debug_print_int("contract capacity not match, output:", info->output_capacity);
        return -99;
      }
    }
  } else {
    /* Check current contract's call_index reach the end */
  }
  return 0;
}

/* =================== */
/* ==== callbacks ==== */
/* =================== */
struct evmc_tx_context get_tx_context(struct evmc_host_context* context) {
  return global_tx_context;
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
  debug_print_data("[get_balance]", address->bytes, 20);
  evmc_uint256be balance{};
  contract_info *info = NULL;
  find_contract_info(&info, global_info_list, global_info_count, address);
  if (info != NULL) {
    debug_print("load balance from contract");
    intx::uint256 value = info->input_balance;
    intx::be::store(balance.bytes, value);
  } else {
    debug_print("load balance from EoA accout");
    eoa_account *account = NULL;
    find_eoa_account(&account, global_eoa_list, global_eoa_count, address);
    if (account == NULL) {
      context->callback_errno = -109;
      return balance;
    }
    intx::uint256 value = account->input_balance;
    intx::be::store(balance.bytes, value);
  }
  debug_print_data("[get_balance], value:", balance.bytes, 32);
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
  debug_print_int("call().kind : ", msg->kind);
  debug_print_int("call().flags: ", msg->flags);
  debug_print_int("call().depth: ", msg->depth);
  debug_print_data("call().sender     : ", msg->sender.bytes, 20);
  debug_print_data("call().destination: ", msg->destination.bytes, 20);
  debug_print_data("call().value      : ", msg->value.bytes, 32);
  debug_print_data("call().input      : ", msg->input_data, msg->input_size);

  int ret;
  struct evmc_result res{};
  contract_info *sender_info = NULL;
  contract_info *dest_info = NULL;

  evmc_address *sender_addr = (evmc_address *)&msg->sender;
  if (msg->kind == EVMC_DELEGATECALL) {
    sender_addr = &global_current_contract;
  }
  if (memcmp(sender_addr->bytes, global_current_contract.bytes, 20) != 0) {
    /* unexpected sender */
    res.status_code = EVMC_REVERT;
    return res;
  }
  find_contract_info(&sender_info, global_info_list, global_info_count, sender_addr);
  if (sender_info == NULL) {
    res.status_code = EVMC_REVERT;
    return res;
  }

  contract_program *program = sender_info->current_program;
  call_record call = program->calls[program->call_index];
  evmc_address destination{};
  if (is_create(msg->kind)) {
    /* TODO: security check */
    memcpy(destination.bytes, call.destination.bytes, 20);
  } else {
    memcpy(destination.bytes, msg->destination.bytes, 20);
  }

  /* Handle value transfer */
  bool transfer_only = !is_create(msg->kind) && msg->input_size == 0;
  ret = verify_call_value(&call, msg);
  if (ret != CKB_SUCCESS) {
    res.status_code = EVMC_REVERT;
    return res;
  }
  if (call.value > 0) {
    ret = contract_info_sub_balance(sender_info, call.value);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
    if (transfer_only) {
      if (call.is_eoa) {
        /* transfer value to EoA account */
        eoa_account *dest_account = NULL;
        find_eoa_account(&dest_account, global_eoa_list, global_eoa_count, &msg->destination);
        if (dest_account == NULL) {
          res.status_code = EVMC_REVERT;
        }
        eoa_account_add_balance(dest_account, call.value);
      } else {
        /* transfer value to contract account */
        find_contract_info(&dest_info, global_info_list, global_info_count, &destination);
        if (dest_info == NULL) {
          res.status_code = EVMC_REVERT;
        }
        contract_info_add_balance(dest_info, call.value);
        /* next program */
        dest_info->current_program = dest_info->current_program->next_program;
        dest_info->program_index += 1;
      }
      program->call_index += 1;
      return res;
    } else if (call.transfer_only != transfer_only) {
      debug_print("current call is not transfer only");
      res.status_code = EVMC_REVERT;
      return res;
    }
  }

  find_contract_info(&dest_info, global_info_list, global_info_count, &destination);
  if (dest_info == NULL) {
    res.status_code = EVMC_REVERT;
    return res;
  }
  if (call.value > 0) {
    contract_info_add_balance(dest_info, call.value);
  }

  /*  1. Increase current_program.call_index
   *  2. Recursively increase sub-contract program_index and programs' call_index
   */
  contract_program *saved_current_program = sender_info->current_program;
  size_t saved_program_index = sender_info->program_index;
  if (is_special_call(msg->kind)) {
    struct evmc_vm *vm = evmc_create_evmone();
    sender_info->special_call_count += 1;
    contract_program *current_program = saved_current_program;
    size_t current_index = saved_program_index;
    for (size_t i = 0; i < sender_info->special_call_count; i++) {
      current_program = current_program->next_program;
      current_index += 1;
    }
    sender_info->current_program = current_program;
    sender_info->program_index = current_index;
    debug_print_int(">> run special program_index", current_index);
    res = vm->execute(vm, context->interface, context, EVMC_MAX_REVISION, msg, dest_info->code_data, dest_info->code_size);
    /* Verify return data */
    if (sender_info->current_program->return_data_size != res.output_size) {
      res.status_code = EVMC_REVERT;
      return res;
    }
    if (memcmp(sender_info->current_program->return_data, res.output_data, res.output_size) != 0) {
      res.status_code = EVMC_REVERT;
      return res;
    }
  }

  if (global_current_is_main) {
    /* TODO: refactor this logic (remove `saved_xxx`) */
    contract_info *active_info = dest_info;
    if (is_special_call(msg->kind)) {
      active_info = sender_info;
    }
    contract_program *saved_dest_current_program = dest_info->current_program;
    size_t saved_dest_program_index = dest_info->program_index;
    ret = contract_info_process_calls(active_info, global_info_list, global_info_count, global_eoa_list, global_eoa_count);
    dest_info->current_program = saved_dest_current_program;
    dest_info->program_index = saved_dest_program_index;
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }

    sender_info->current_program = saved_current_program;
    sender_info->program_index = saved_program_index;
    ret = contract_info_call(sender_info, dest_info, &global_tx_context.tx_origin, msg, &res);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }

    debug_print("[contract_info_next_program] main contract dest_info");
    ret = contract_info_next_program(dest_info);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
  } else {
    sender_info->current_program = saved_current_program;
    sender_info->program_index = saved_program_index;
    /* Increase destination contract's program_index fit sender's call record */
    ret = contract_info_reach_program(sender_info, dest_info);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
    ret = contract_info_call(sender_info, dest_info, &global_tx_context.tx_origin, msg, &res);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
    debug_print("[contract_info_next_program] sub contract dest_info");
    ret = contract_info_next_program(dest_info);
    if (ret != CKB_SUCCESS) {
      res.status_code = EVMC_REVERT;
      return res;
    }
  }
  return res;
}

evmc_bytes32 get_block_hash(struct evmc_host_context* context, int64_t number) {
  uint64_t block_number = (uint64_t) number;
  for (size_t i = 0; i < global_header_count; i++) {
    if (global_header_infos[i].number == block_number) {
      return global_header_infos[i].hash;
    }
  }
  evmc_bytes32 zero_block_hash{};
  return zero_block_hash;
}

void emit_log(struct evmc_host_context* context,
              const evmc_address* address,
              const uint8_t* data,
              size_t data_size,
              const evmc_bytes32 topics[],
              size_t topics_count) {
  /* Do nothing */
}

int load_account_infos(blake2b_state *blake2b_ctx) {
  int ret;
  uint64_t len;
  /* Load current contract address */
  uint8_t witness_buf[WITNESS_SIZE];
  uint8_t script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_checked_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    debug_print("load current script failed");
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
  uint8_t lock_script[SCRIPT_SIZE];
  uint8_t cell_data[128];
  size_t input_index = 0;
  uint64_t capacity;
  uint64_t balance;
  uint64_t type_script_size;
  uint64_t lock_script_size;
  uint64_t type_script_capacity;
  uint64_t lock_script_capacity;
  uint64_t cell_data_size;
  while (1) {
    if (global_info_count >= MAX_CONTRACT_COUNT) {
      debug_print("too many contract in one transaction");
      return -100;
    }

    len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(type_script, &len, 0, input_index, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      debug_print("load inputs finished");
      break;
    } else if (ret == CKB_ITEM_MISSING) {
      debug_print_int("ignore input", input_index);
      input_index += 1;
      continue;
    } else if (ret != CKB_SUCCESS) {
      debug_print_int("load type script from input failed", input_index);
      return ret;
    }
    type_script_size = len;
    type_script_capacity = script_occupied_capacity(type_script, len);

    /* capacity */
    len = 8;
    ret = ckb_load_cell_by_field(&capacity, &len, 0, input_index, CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      debug_print_int("load capacity failed, ret:", ret);
      return ret;
    }
    if (len != 8) {
      debug_print_int("load capacity invlaid len:", len);
      return -100;
    }
    /* lock script size */
    len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(&lock_script, &len, 0, input_index, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK);
    if (ret != CKB_SUCCESS) {
      debug_print_int("load lock script failed, ret:", ret);
      return ret;
    }
    lock_script_size = len;
    lock_script_capacity = script_occupied_capacity(lock_script, len);
    /* cell data size */
    len = 128;
    ret = ckb_load_cell_data(&cell_data, &len, 0, input_index, CKB_SOURCE_INPUT);
    if (ret != CKB_SUCCESS) {
      debug_print_int("load cell data failed, ret:", ret);
      return ret;
    }
    cell_data_size = len;
    if (capacity < (8 + type_script_capacity + lock_script_capacity + cell_data_size)) {
      debug_print("this is impossible!!!");
      return -100;
    }
    balance = capacity - (8 + type_script_capacity + lock_script_capacity + cell_data_size) * ONE_CKB;
    debug_print_int("input balance", balance);
    debug_print_int("input capacity", capacity);

    debug_print_int("loaded input", input_index);
    bool code_matched = false;
    ret = check_script_code(script, script_size, type_script, type_script_size, &code_matched);
    if (ret != CKB_SUCCESS) {
      debug_print_int("check type script from input failed, input index:", input_index);
      return ret;
    }
    if (code_matched) {
      if (cell_data_size != 64) {
        debug_print_int("contract cell data invlaid len:", cell_data_size);
        return -100;
      }

      mol_seg_t script_seg;
      script_seg.ptr = type_script;
      script_seg.size = type_script_size;
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
      info->input_capacity = capacity;
      info->input_balance = balance;
      debug_print_int("info->input_capacity", info->input_capacity);
      debug_print_int("info->input_balance", info->input_balance);
      debug_print_data("info->address", info->address.bytes, 20);
      debug_print("parse input contract info finished");
      global_info_count += 1;
    } else {
      bool is_eoa = false;
      evmc_address eoa_address;
      mol_seg_t type_args_bytes_seg;
      mol_seg_t lock_args_bytes_seg;
      ret = check_eoa_script(blake2b_ctx,
                             type_script,
                             type_script_size,
                             lock_script,
                             lock_script_size,
                             &is_eoa,
                             &eoa_address,
                             &lock_args_bytes_seg,
                             &type_args_bytes_seg);
      if (ret != CKB_SUCCESS) {
        debug_print_int("check eoa script failed, input index:", input_index);
        return ret;
      }
      if (is_eoa) {
        debug_print_data("eoa->address", eoa_address.bytes, 20);
        eoa_account *account = global_eoa_list + global_eoa_count;
        eoa_account_init(account,
                         &eoa_address,
                         &type_args_bytes_seg,
                         &lock_args_bytes_seg,
                         balance,
                         capacity,
                         input_index);
        global_eoa_count += 1;
      }
    }

    input_index += 1;
  }

  size_t output_index = 0;
  while (1) {
    if (global_info_count >= MAX_CONTRACT_COUNT) {
      debug_print("too many contract in one transaction");
      return -100;
    }
    len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(type_script, &len, 0, output_index, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      debug_print("load outputs finished");
      break;
    } else if (ret == CKB_ITEM_MISSING) {
      debug_print_int("ignore output", output_index);
      output_index += 1;
      continue;
    } else if (ret != CKB_SUCCESS) {
      debug_print_int("load type script from output failed", output_index);
      return ret;
    }
    type_script_size = len;
    type_script_capacity = script_occupied_capacity(type_script, len);

    /* capacity */
    len = 8;
    ret = ckb_load_cell_by_field(&capacity, &len, 0, output_index, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      debug_print_int("load capacity failed, ret:", ret);
      return ret;
    }
    if (len != 8) {
      debug_print_int("load capacity invlaid len:", len);
      return -100;
    }
    /* lock script size */
    len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(&lock_script, &len, 0, output_index, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK);
    if (ret != CKB_SUCCESS) {
      debug_print_int("load lock script failed, ret:", ret);
      return ret;
    }
    lock_script_size = len;
    lock_script_capacity = script_occupied_capacity(lock_script, len);
    /* cell data size */
    len = 128;
    ret = ckb_load_cell_data(&cell_data, &len, 0, output_index, CKB_SOURCE_OUTPUT);
    if (ret != CKB_SUCCESS) {
      debug_print_int("load cell data failed, ret:", ret);
      return ret;
    }
    cell_data_size = len;
    if (capacity < (8 + type_script_capacity + lock_script_capacity + cell_data_size)) {
      debug_print("this is impossible!!!");
      return -100;
    }
    balance = capacity - (8 + type_script_capacity + lock_script_capacity + cell_data_size) * ONE_CKB;
    debug_print_int("output balance", balance);
    debug_print_int("output capacity", capacity);

    debug_print_int("loaded output", output_index);
    bool code_matched = false;
    ret = check_script_code(script, script_size, type_script, type_script_size, &code_matched);
    if (ret != CKB_SUCCESS) {
      debug_print_int("checkout type script from output failed", output_index);
      return ret;
    }
    if (code_matched) {
      if (cell_data_size != 64) {
        debug_print_int("contract cell data invlaid len:", cell_data_size);
        return -100;
      }

      mol_seg_t script_seg;
      script_seg.ptr = type_script;
      script_seg.size = type_script_size;
      mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
      mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
      if (args_bytes_seg.size != CSAL_SCRIPT_ARGS_LEN) {
        return ERROR_INVALID_DATA;
      }
      evmc_address tmp_addr = *(evmc_address *)args_bytes_seg.ptr;
      debug_print_data("args_bytes_seg", args_bytes_seg.ptr, 20);
      debug_print_data("tmp_addr", tmp_addr.bytes, 20);
      contract_info *info = NULL;
      find_contract_info(&info, global_info_list, global_info_count, &tmp_addr);
      if (info == NULL) {
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
        info = global_info_list + global_info_count;
        ret = contract_info_init(info, content_bytes_seg.ptr, content_bytes_seg.size, &tmp_addr);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        info->is_create = true;
        debug_print_data("info->address", info->address.bytes, 20);
        debug_print("parse output contract info finished");
        global_info_count += 1;
      }
      info->output_capacity = capacity;
      info->output_balance = balance;
    } else {
      bool is_eoa = false;
      evmc_address eoa_address;
      mol_seg_t type_args_bytes_seg;
      mol_seg_t lock_args_bytes_seg;
      ret = check_eoa_script(blake2b_ctx,
                             type_script,
                             type_script_size,
                             lock_script,
                             lock_script_size,
                             &is_eoa,
                             &eoa_address,
                             &type_args_bytes_seg,
                             &lock_args_bytes_seg);
      if (ret != CKB_SUCCESS) {
        debug_print_int("check eoa script failed, input index:", input_index);
        return ret;
      }
      if (is_eoa) {
        debug_print_data("eoa->address", eoa_address.bytes, 20);
        eoa_account *account = NULL;
        find_eoa_account(&account, global_eoa_list, global_eoa_count, &eoa_address);
        if (account == NULL) {
          debug_print_data("eoa account not in inputs", eoa_address.bytes, 20);
          return -100;
        }
        account->output_balance = balance;
        account->output_capacity = capacity;
        account->output_index = output_index;
      }
    }
    output_index += 1;
  }

  return 0;
}

int verify_signature_count() {
  uint8_t zero_signature[65];
  memset(zero_signature, 0, 65);
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
          debug_print("main signature is not in first program");
          return -100;
        }
        if ((info->program_count - info->special_call_total_count) != 1) {
          debug_print("main contract only allow 1 normal(not CALLCODE/DELEGATECALL) program");
          return -100;
        }
        if (has_entrance_signature) {
          debug_print("has multiple entrance signature");
          return -100;
        }
        if (memcmp(global_current_contract.bytes, info->address.bytes, 20) == 0) {
          global_current_is_main = true;
        }
        info->is_main = true;
        memcpy(global_tx_context.tx_origin.bytes, current_program->tx_origin.bytes, 20);
        has_entrance_signature = true;
      }
      current_program = current_program->next_program;
    }
  }
  if (!has_entrance_signature) {
    debug_print("no entrance signature found");
    return -100;
  }
  return 0;
}

int verify_contract_code(blake2b_state *blake2b_ctx,
                         uint8_t call_kind,
                         const evmc_address *destination,
                         const uint32_t code_size,
                         const uint8_t *code_data) {
  /*
   * - verify code_hash not changed
   * - verify code_hash in data filed match the blake2b_h256(code_data)
   */
  int ret;
  uint64_t len;
  if (call_kind == EVMC_CALL
      || (is_special_call(call_kind)
          && memcmp(destination->bytes, global_current_contract.bytes, 20) == 0)) {
    uint8_t code_hash[32];
    blake2b_init(blake2b_ctx, 32);
    blake2b_update(blake2b_ctx, code_data, code_size);
    blake2b_final(blake2b_ctx, code_hash, 32);
    debug_print_data("code: ", code_data, code_size);
    debug_print_data("code_hash: ", code_hash, 32);

    uint8_t hash[32];
    len = 32;
    ret = ckb_load_cell_data(hash, &len, 32, 0, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
      debug_print("load cell data from input failed");
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
      if (len != 32) {
        return -102;
      }
      debug_print_data("output code hash: ", hash, 32);
      if (memcmp(code_hash, hash, 32) != 0) {
        return -103;
      }
    } else if (ret != CKB_INDEX_OUT_OF_BOUND) {
      debug_print("load cell data from output failed");
      return ret;
    }
  }
  return 0;
}

int load_headers(blake2b_state *blake2b_ctx) {
  /* Load latest header information */
  int ret;
  uint64_t len;
  uint8_t header_buffer[HEADER_SIZE];
  size_t input_index = 0;
  while(1) {
    /* Load header by inputs */
    len = HEADER_SIZE;
    ret = ckb_load_header(header_buffer, &len, 0, input_index, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      debug_print("load input headers finised");
      break;
    } else if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len > HEADER_SIZE) {
      /* buffer not enough */
      return -10;
    }
    mol_seg_t header_seg;
    header_seg.ptr = (uint8_t *)header_buffer;
    header_seg.size = len;
    mol_seg_t raw_seg = MolReader_Header_get_raw(&header_seg);
    mol_seg_t block_number_seg = MolReader_RawHeader_get_number(&raw_seg);
    uint64_t block_number = *((uint64_t *)block_number_seg.ptr);
    if (block_number > global_max_block_number) {
      global_max_block_number = block_number;
    }
    input_index += 1;
  }

  uint64_t header_index = 0;
  while(1) {
    /* Load header by header dep */
    len = HEADER_SIZE;
    ret = ckb_load_header(header_buffer, &len, 0, header_index, CKB_SOURCE_HEADER_DEP);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      debug_print("load all headers finised");
      break;
    } else if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len > HEADER_SIZE) {
      /* buffer not enough */
      return -10;
    }
    mol_seg_t header_seg;
    header_seg.ptr = (uint8_t *)header_buffer;
    header_seg.size = len;
    mol_seg_t raw_seg = MolReader_Header_get_raw(&header_seg);
    mol_seg_t block_number_seg = MolReader_RawHeader_get_number(&raw_seg);
    uint64_t block_number = *((uint64_t *)block_number_seg.ptr);
    mol_seg_t txs_root_seg = MolReader_RawHeader_get_transactions_root(&raw_seg);
    evmc_bytes32 txs_root = *((evmc_bytes32 *)txs_root_seg.ptr);

    evmc_bytes32 block_hash{};
    blake2b_init(blake2b_ctx, 32);
    blake2b_update(blake2b_ctx, header_seg.ptr, header_seg.size);
    blake2b_final(blake2b_ctx, block_hash.bytes, 32);
    global_header_infos[header_index] = header_info{block_number, block_hash, txs_root};

    header_index += 1;
  }
  global_header_count = header_index;

  return 0;
}

int load_tx_context(blake2b_state *blake2b_ctx) {
  int ret;
  uint64_t len = HEADER_SIZE;
  uint8_t header_buffer[HEADER_SIZE];
  ret = ckb_load_header(header_buffer, &len, 0, 0, CKB_SOURCE_HEADER_DEP);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > HEADER_SIZE) {
    /* buffer not enough */
    return -10;
  }

  mol_seg_t header_seg;
  header_seg.ptr = (uint8_t *)header_buffer;
  header_seg.size = len;
  mol_seg_t raw_seg = MolReader_Header_get_raw(&header_seg);
  /* Timestamp */
  mol_seg_t timestamp_seg = MolReader_RawHeader_get_timestamp(&raw_seg);
  uint64_t timestamp = *((uint64_t *)timestamp_seg.ptr) / 1000;
  /* Block Number */
  mol_seg_t block_number_seg = MolReader_RawHeader_get_number(&raw_seg);
  uint64_t block_number = *((uint64_t *)block_number_seg.ptr);
  if (block_number < global_max_block_number) {
    debug_print("First header too old");
    return -11;
  }
  mol_seg_t compact_target_seg = MolReader_RawHeader_get_compact_target(&raw_seg);
  uint32_t compact_target = *((uint32_t *)compact_target_seg.ptr);

  /* already exists */
  global_tx_context.block_number = (int64_t)block_number;
  global_tx_context.block_timestamp = (int64_t)timestamp;
  /* int64_t::MAX */
  global_tx_context.block_gas_limit = 9223372036854775807;
  /* gas_price = 1 wei */
  global_tx_context.tx_gas_price.bytes[31] = 0x01;
  /* TODO block_coinbase */
  /* convert from compact_target */
  global_tx_context.block_difficulty = compact_to_difficulty(compact_target);
  /* chain_id = 1 (mainnet) */
  intx::uint256 chain_id = 1;
  intx::be::store(global_tx_context.chain_id.bytes, chain_id);

  debug_print_data("[block difficulty]", global_tx_context.block_difficulty.bytes, 32);

  /* load coinbase:
      - coinbase can only be found in entrance contract's first program
   */
  tx_coinbase *coinbase = NULL;
  for (size_t i = 0; i < global_info_count; i++) {
    contract_info *info = &global_info_list[i];
    contract_program *program = info->head_program;
    for (size_t j = 0; j < info->program_count; j++) {
      if (info->is_main && j == 0) {
        coinbase = program->coinbase;
      } else if (program->coinbase != NULL){
        debug_print("found coinbase in unexpected place");
        debug_print_int("info index", i);
        debug_print_int("program index", j);
        return -11;
      }
      program = program->next_program;
    }
  }
  if (coinbase == NULL) {
    debug_print("No coinbase found");
  }
  /* Verify coinbase */
  uint32_t proof_index_values[1];
  cbmt_node needed_nodes[1];
  cbmt_proof proof;
  cbmt_indices proof_indices;
  cbmt_node root;
  cbmt_leaves needed_leaves;
  proof_index_values[0] = coinbase->proof_index;
  proof_indices.values = proof_index_values;
  proof_indices.length = 1;
  proof_indices.capacity = 1;
  proof.lemmas_length = coinbase->proof_lemmas_count;
  proof.lemmas = (cbmt_node *)coinbase->proof_lemmas;
  proof.indices = proof_indices;

  memcpy(root.bytes, coinbase->raw_transactions_root.bytes, CBMT_NODE_SIZE);

  blake2b_init(blake2b_ctx, CBMT_NODE_SIZE);
  blake2b_update(blake2b_ctx, coinbase->raw_cellbase_tx, coinbase->raw_cellbase_tx_size);
  blake2b_final(blake2b_ctx, (&needed_nodes[0])->bytes, CBMT_NODE_SIZE);
  cbmt_leaves_init(&needed_leaves, needed_nodes, 1);

  cbmt_node nodes[8];
  cbmt_node_pair pairs[8];
  cbmt_buffer nodes_buffer;
  cbmt_buffer pairs_buffer;
  cbmt_buffer_init(&nodes_buffer, nodes, sizeof(nodes));
  cbmt_buffer_init(&pairs_buffer, pairs, sizeof(pairs));
  ret = cbmt_proof_verify(&proof, &root, &needed_leaves, node_merge, blake2b_ctx, nodes_buffer, pairs_buffer);
  if (ret != CKB_SUCCESS) {
    debug_print_int("coinbase proof verify failed", ret);
    return ret;
  }
  cbmt_node nodes2[8];
  cbmt_buffer nodes2_buffer;
  cbmt_buffer_init(&nodes2_buffer, nodes2, sizeof(nodes));
  cbmt_node txs_root;
  cbmt_leaves leaves;
  cbmt_node leaf_nodes[2];
  memcpy((&leaf_nodes[0])->bytes, coinbase->raw_transactions_root.bytes, CBMT_NODE_SIZE);
  memcpy((&leaf_nodes[1])->bytes, coinbase->witnesses_root.bytes, CBMT_NODE_SIZE);
  debug_print_data("leaf_nodes[0]", leaf_nodes[0].bytes, 32);
  debug_print_data("leaf_nodes[1]", leaf_nodes[1].bytes, 32);
  cbmt_leaves_init(&leaves, leaf_nodes, 2);
  ret = cbmt_build_merkle_root(&txs_root, &leaves, node_merge, blake2b_ctx, nodes2_buffer);
  if (ret != 0) {
    debug_print("build merkle root failed");
    return ret;
  }
  mol_seg_t transactions_root = MolReader_RawHeader_get_transactions_root(&raw_seg);
  if (memcmp(txs_root.bytes, transactions_root.ptr, 32) != 0) {
    debug_print("transactions root not match");
    debug_print_data("txs_root", txs_root.bytes, 32);
    debug_print_data("transactions_root", transactions_root.ptr, 32);
    return -11;
  }

  mol_seg_t raw_tx_seg;
  raw_tx_seg.ptr = coinbase->raw_cellbase_tx;
  raw_tx_seg.size = coinbase->raw_cellbase_tx_size;
  ret = MolReader_RawTransaction_verify(&raw_tx_seg, false);
  if (ret != 0) {
    debug_print("The raw_cellbase_tx data is not a validate molecule RawTransaction");
    return ret;
  }
  mol_seg_t inputs_seg = MolReader_RawTransaction_get_inputs(&raw_tx_seg);
  mol_seg_t outputs_seg = MolReader_RawTransaction_get_outputs(&raw_tx_seg);
  uint32_t inputs_length = MolReader_CellInputVec_length(&inputs_seg);
  uint32_t outputs_length = MolReader_CellOutputVec_length(&outputs_seg);
  if (inputs_length != 1 || outputs_length > 1) {
    debug_print("Cellbase has only one input and less than 1 output");
    return -11;
  }
  mol_seg_res_t first_input_res = MolReader_CellInputVec_get(&inputs_seg, 0);
  uint8_t input_res_errno = *(uint8_t *)(&first_input_res);
  if (input_res_errno != 0) {
    debug_print_int("error when get first input", input_res_errno);
    return input_res_errno;
  }
  mol_seg_t first_input_seg = first_input_res.seg;
  mol_seg_t previous_outpoint_seg = MolReader_CellInput_get_previous_output(&first_input_seg);
  mol_seg_t previous_tx_hash_seg = MolReader_OutPoint_get_tx_hash(&previous_outpoint_seg);
  mol_seg_t previous_index_seg = MolReader_OutPoint_get_index(&previous_outpoint_seg);
  uint32_t previous_index = *(uint32_t *)previous_index_seg.ptr;
  evmc_bytes32 zero_hash;
  memset(zero_hash.bytes, 0, 32);
  if (memcmp(previous_tx_hash_seg.ptr, zero_hash.bytes, 32) != 0) {
    debug_print_data("invalid cellbase input previous_outpoint tx_hash", previous_tx_hash_seg.ptr, 32);
    return -11;
  }
  if (previous_index != UINT32_MAX) {
    debug_print_int("Invalid cellbase input previous_outpoint index", previous_index);
    return -11;
  }

  if (outputs_length == 1) {
    mol_seg_res_t first_output_res = MolReader_CellOutputVec_get(&outputs_seg, 0);
    uint8_t output_res_errno = *(uint8_t *)(&first_output_res);
    if (output_res_errno != 0) {
      debug_print_int("error when get first output", output_res_errno);
      return output_res_errno;
    }
    mol_seg_t first_output_seg = first_output_res.seg;
    mol_seg_t output_lock_seg = MolReader_CellOutput_get_lock(&first_output_seg);
    mol_seg_t lock_code_hash_seg = MolReader_Script_get_code_hash(&output_lock_seg);
    mol_seg_t lock_hash_type_seg = MolReader_Script_get_hash_type(&output_lock_seg);
    mol_seg_t lock_args_seg = MolReader_Script_get_args(&output_lock_seg);
    mol_seg_t lock_args_bytes_seg = MolReader_Bytes_raw_bytes(&lock_args_seg);
    /* 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8 */
    static uint8_t secp_blake160_code_hash[32]
      = {0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0,
         0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
         0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63,
         0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8};
    if (memcmp(secp_blake160_code_hash, lock_code_hash_seg.ptr, 32) != 0) {
      debug_print_data("[note]: code_hash not match", lock_code_hash_seg.ptr, 32);
    } else if (*lock_hash_type_seg.ptr != 1) {
      debug_print_int("[note]: hash_type not match", *lock_hash_type_seg.ptr);
    } else if (lock_args_bytes_seg.size != 20) {
      debug_print_int("[note]: lock args length not match", lock_args_bytes_seg.size);
    } else {
      debug_print_data("tx_context.block_coinbase", lock_args_bytes_seg.ptr, 20);
      memcpy(global_tx_context.block_coinbase.bytes, lock_args_bytes_seg.ptr, 20);
    }
  }
  return 0;
}

inline int verify_params(const uint8_t *signature_data,
                         const uint8_t call_kind,
                         const uint32_t flags,
                         const uint32_t depth,
                         const evmc_address *tx_origin,
                         const evmc_address *sender,
                         const evmc_address *destination,
                         const evmc_uint256be *value,
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
  debug_print_data("value: ", value->bytes, 32);
  debug_print_data("code : ", code_data, code_size);
  debug_print_data("input: ", input_data, input_size);

  int ret;
  uint64_t len;
  blake2b_state blake2b_ctx;
  uint8_t witness_buf[WITNESS_SIZE];

  if (!global_touched) {
    debug_print("initializing ...");

    /* contract and EoA infos */
    ret = load_account_infos(&blake2b_ctx);
    if (ret != CKB_SUCCESS) {
      return ret;
    }

    ret = verify_signature_count();
    if (ret != CKB_SUCCESS) {
      return ret;
    }

    ret = verify_contract_code(&blake2b_ctx, call_kind, destination, code_size, code_data);
    if (ret != CKB_SUCCESS) {
      return ret;
    }

    ret = load_headers(&blake2b_ctx);
    if (ret != CKB_SUCCESS) {
      return ret;
    }

    ret = load_tx_context(&blake2b_ctx);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  eoa_account *tx_origin_account = NULL;
  find_eoa_account(&tx_origin_account, global_eoa_list, global_eoa_count, tx_origin);
  if (tx_origin_account == NULL) {
    debug_print("can not find tx_origin account");
    return -99;
  }

  /* Change tx_origin balance */
  if (global_current_is_main) {
    intx::uint256 transfer_value_u256 = intx::be::load<intx::uint256>(value->bytes);
    uint64_t transfer_value = transfer_value_u256.lo.lo;
    if (transfer_value > 0) {
      ret = eoa_account_sub_balance(tx_origin_account, transfer_value);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      contract_info *info = NULL;
      find_contract_info(&info, global_info_list, global_info_count, destination);
      if (info == NULL) {
        debug_print_data("can not find entrance destination contract", destination->bytes, 20);
        return -99;
      }
      contract_info_add_balance(info, transfer_value);
    }
    for (size_t idx = 0; idx < global_info_count; idx++) {
      contract_info *info = &global_info_list[idx];
      contract_program *current_program = info->head_program;
      if (is_create(current_program->kind)) {
        ret = eoa_account_sub_balance(tx_origin_account, (info->output_capacity - info->output_balance));
        if (ret != CKB_SUCCESS) {
          return ret;
        }
      }
    }
  }

  /* Verify sender by signature field */
  if (global_current_is_main) {
    if (is_special_call(call_kind)) {
      /* do nothing */
      debug_print("special call don't verify sender signature");
    } else {
      debug_print("Verify EoA sender signature");
      uint8_t tx_hash[32];
      len = 32;
      ret = ckb_load_tx_hash(tx_hash, &len, 0);
      if (ret != CKB_SUCCESS) {
        debug_print("load tx hash failed");
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

      eoa_account *account = NULL;
      find_eoa_account(&account, global_eoa_list, global_eoa_count, tx_origin);
      if (account == NULL) {
        return -95;
      }
      if (memcmp(account->lock_args, temp, 20) != 0) {
        debug_print_data("account->lock_args", account->lock_args, 20);
        debug_print_data("temp", temp, 20);
        debug_print("Signature pubkey not match lock script args");
        return -95;
      }

      uint8_t hash[32];
      blake2b_init(&blake2b_ctx, 32);
      blake2b_update(&blake2b_ctx, account->type_args, 32);
      blake2b_update(&blake2b_ctx, temp, 20);
      blake2b_final(&blake2b_ctx, hash, 32);

      /* Verify entrance program sender */
      if (memcmp(sender->bytes, hash, 20) != 0) {
        debug_print("EoA sender not match the signature");
        return -95;
      }
      /* Verify tx_origin */
      if (memcmp(sender->bytes, tx_origin->bytes, 20) != 0) {
        debug_print("Sender is not tx_origin");
        return -96;
      }
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
      debug_print("Can not found sender contract in sub contract");
      return -100;
    }
  }

  /* Verify tx_origin all the same */
  if (memcmp(global_tx_context.tx_origin.bytes, tx_origin->bytes, 20) != 0) {
    /* tx_origin not the same */
    return -97;
  }

  /* Verify destination match current script args */
  if (!is_special_call(call_kind)
      && memcmp(destination->bytes, global_current_contract.bytes, CSAL_SCRIPT_ARGS_LEN) != 0) {
    debug_print("ERROR: destination not match current script args");
    return -98;
  }


  if (!global_touched) {
    global_touched = true;
  }
  return 0;
}

inline void context_init(struct evmc_host_context* context,
                         struct evmc_vm *_vm,
                         struct evmc_host_interface *interface,
                         evmc_address tx_origin,
                         csal_change_t *existing_values,
                         csal_change_t *changes) {
  context->callback_errno = 0;
  context->interface = interface;
  context->existing_values = existing_values;
  context->changes = changes;
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
  if (context->callback_errno != CKB_SUCCESS) {
    debug_print_int("callback error", context->callback_errno);
    return context->callback_errno;
  }

  int ret;
  if (is_create(msg->kind)) {
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
    debug_print("can not found contract info");
    return -111;
  }
  /* Verify res.output_data match the program.return_data */
  if (res->output_size != info->current_program->return_data_size) {
    debug_print("return data size not match");
    return -111;
  }
  debug_print_data("output_data", res->output_data, res->output_size);
  debug_print_data("return_data", info->current_program->return_data, res->output_size);
  if (memcmp(res->output_data, info->current_program->return_data, res->output_size) != 0) {
    debug_print("return data not match");
    return -111;
  }

  debug_print("[contract_info_next_program] verify_result");
  ret = contract_info_next_program(info);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (info->program_index == info->program_count) {
    ret = contract_info_list_verify_complete(global_info_list, global_info_count);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = eoa_account_list_verify_complete(global_eoa_list, global_eoa_count);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  /* Reset special call count */
  info->special_call_count = 0;

  return 0;
}
