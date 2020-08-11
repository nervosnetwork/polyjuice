#include <evmc/evmc.h>

#include "generator.h"
#include <stdlib.h>

#define _CSAL_RETURN_SYSCALL_NUMBER 3075
#define _CSAL_LOG_SYSCALL_NUMBER 3076
#define _CSAL_SELFDESTRUCT_SYSCALL_NUMBER 3077
#define _CSAL_CALL_SYSCALL_NUMBER 3078
#define _CSAL_GET_CODE_SIZE_SYSCALL_NUMBER 3079
#define _CSAL_COPY_CODE_SYSCALL_NUMBER 3080
#define _CSAL_GET_BLOCK_HASH 3081
#define _CSAL_GET_TX_CONTEXT 3082

static char debug_buffer[64 * 1024];
static void debug_print_data(const char *prefix,
                             const uint8_t *data,
                             uint32_t data_len) {
  int offset = 0;
  offset += sprintf(debug_buffer, "%s 0x", prefix);
  for (size_t i = 0; i < data_len; i++) {
    offset += sprintf(debug_buffer + offset, "%02x", data[i]);
  }
  debug_buffer[offset] = '\0';
  ckb_debug(debug_buffer);
}
static void debug_print_int(const char *prefix, int64_t ret) {
  sprintf(debug_buffer, "%s => %ld", prefix, ret);
  ckb_debug(debug_buffer);
}

int csal_return(const uint8_t *data, uint32_t data_length) {
  return syscall(_CSAL_RETURN_SYSCALL_NUMBER, data, data_length, 0, 0, 0, 0);
}
int csal_log(const uint8_t *data, uint32_t data_length) {
  return syscall(_CSAL_LOG_SYSCALL_NUMBER, data, data_length, 0, 0, 0, 0);
}
int csal_selfdestruct(const uint8_t *data, uint32_t data_length) {
  return syscall(_CSAL_SELFDESTRUCT_SYSCALL_NUMBER, data, data_length, 0, 0, 0, 0);
}
int csal_call(uint8_t *result_data, const uint8_t *msg_data) {
  return syscall(_CSAL_CALL_SYSCALL_NUMBER, result_data, msg_data, 0, 0, 0, 0);
}
int csal_get_code_size(uint8_t *address, uint32_t *code_size) {
  return syscall(_CSAL_GET_CODE_SIZE_SYSCALL_NUMBER, address, code_size, 0, 0, 0, 0);
}
int csal_copy_code(uint8_t *address, uint32_t code_offset, uint8_t *buffer_data, uint32_t buffer_size, uint32_t *done_size) {
  return syscall(_CSAL_COPY_CODE_SYSCALL_NUMBER, address, code_offset, buffer_data, buffer_size, done_size, 0);
}
int csal_get_block_hash(evmc_bytes32* block_hash, int64_t number) {
  return syscall(_CSAL_GET_BLOCK_HASH, block_hash, number, 0, 0, 0, 0);
}
int csal_get_tx_context(uint8_t *buffer) {
  return syscall(_CSAL_GET_TX_CONTEXT, buffer, 0, 0, 0, 0, 0);
}


void release_result(const struct evmc_result* result) {
  free((void *)result->output_data);
}


struct evmc_host_context {
  csal_change_t *existing_values;
  csal_change_t *changes;
  evmc_address tx_origin;
  bool destructed;
};

struct evmc_tx_context get_tx_context(struct evmc_host_context* context) {
  struct evmc_tx_context ctx{};
  ctx.tx_origin = context->tx_origin;

  uint8_t buffer[1024];
  int ret = csal_get_tx_context(buffer);
  if (ret != 0) {
    ckb_debug("csal_get_tx_context error");
  }
  uint8_t *ctx_ptr = buffer;
  uint64_t block_number = *(uint64_t *)ctx_ptr;
  ctx_ptr += 8;
  uint64_t block_timestamp = *(uint64_t *)ctx_ptr;
  ctx_ptr += 8;
  ctx.block_number = (int64_t)block_number;
  ctx.block_timestamp = (int64_t)block_timestamp;
  memcpy(ctx.block_difficulty.bytes, ctx_ptr, 32);
  ctx_ptr += 32;
  memcpy(ctx.chain_id.bytes, ctx_ptr, 32);
  ctx_ptr += 32;
  /* int64_t::MAX */
  ctx.block_gas_limit = 9223372036854775807;

  debug_print_int("[block number]", block_number);
  debug_print_int("[block timestamp]", block_timestamp);
  debug_print_data("[block difficulty]", ctx.block_difficulty.bytes, 32);
  debug_print_data("[chain id]", ctx.chain_id.bytes, 32);
  return ctx;
}

bool account_exists(struct evmc_host_context* context,
                    const evmc_address* address) {
  return true;
}

evmc_bytes32 get_storage(struct evmc_host_context* context,
                         const evmc_address* address,
                         const evmc_bytes32* key) {
  debug_print_data("[get_storage] address", address->bytes, 20);
  debug_print_data("[get_storage]     key", key->bytes, 32);
  evmc_bytes32 value{};
  int ret;
  ret = csal_change_fetch(context->changes, key->bytes, value.bytes);
  if (ret != 0) {
    ret = csal_change_fetch(context->existing_values, key->bytes, value.bytes);
  }
  return value;
}

enum evmc_storage_status set_storage(struct evmc_host_context* context,
                                     const evmc_address* address,
                                     const evmc_bytes32* key,
                                     const evmc_bytes32* value) {
  /* int _ret; */
  debug_print_data("[set_storage] address", address->bytes, 20);
  debug_print_data("[set_storage]     key", key->bytes, 32);
  debug_print_data("[set_storage]   value", value->bytes, 32);
  csal_change_insert(context->existing_values, key->bytes, value->bytes);
  csal_change_insert(context->changes, key->bytes, value->bytes);
  return EVMC_STORAGE_ADDED;
}

size_t get_code_size(struct evmc_host_context* context,
                     const evmc_address* address) {
  uint32_t code_size = 0;
  int ret = csal_get_code_size((uint8_t *)address->bytes, &code_size);
  debug_print_int("code size", code_size);
  if (ret != CKB_SUCCESS) {
    ckb_debug("get code size failed");
    return 0;
  }
  return (size_t)code_size;
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
  uint32_t done_size = 0;
  int ret = csal_copy_code((uint8_t *)address->bytes,
                           (uint32_t)code_offset,
                           buffer_data,
                           (uint32_t)buffer_size,
                           &done_size);
  if (ret != CKB_SUCCESS) {
    ckb_debug("copy_code failed");
    return 0;
  }
  return (size_t)done_size;
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
  context->destructed = true;
  csal_selfdestruct(beneficiary->bytes, 20);
}

struct evmc_result call(struct evmc_host_context* context,
                        const struct evmc_message* msg) {
  uint8_t result_data[100 * 1024];
  uint8_t msg_data[100 * 1024];
  uint8_t *msg_ptr = msg_data;

  debug_print_int("kind", (int)msg->kind);
  debug_print_data("sender", msg->sender.bytes, 20);
  debug_print_data("destination", msg->destination.bytes, 20);
  debug_print_data("input data", msg->input_data, msg->input_size);

  *msg_ptr = (uint8_t)msg->kind;
  msg_ptr += 1;
  memcpy(msg_ptr, ((uint8_t *)&msg->flags), 4);
  msg_ptr += 4;
  memcpy(msg_ptr, ((uint8_t *)&msg->depth), 4);
  msg_ptr += 4;
  memcpy(msg_ptr, ((uint8_t *)&msg->gas), 8);
  msg_ptr += 8;
  memcpy(msg_ptr, &msg->destination.bytes, 20);
  msg_ptr += 20;
  memcpy(msg_ptr, &msg->sender.bytes, 20);
  msg_ptr += 20;

  uint32_t input_size = (uint32_t) msg->input_size;
  memcpy(msg_ptr, ((uint8_t *)&input_size), 4);
  msg_ptr += 4;
  memcpy(msg_ptr, msg->input_data, msg->input_size);
  msg_ptr += msg->input_size;
  memcpy(msg_ptr, &msg->value.bytes, 32);
  msg_ptr += 32;
  memcpy(msg_ptr, &msg->create2_salt.bytes, 32);
  csal_call(result_data, msg_data);

  uint8_t *result_ptr = result_data;
  int32_t output_size_32 = *((int32_t *)result_ptr);
  result_ptr += 4;

  size_t output_size = (size_t)output_size_32;
  uint8_t *output_data = (uint8_t *)malloc(output_size);
  memcpy(output_data, result_ptr, output_size);
  result_ptr += output_size;

  evmc_address create_address{};
  memcpy(&create_address.bytes, result_ptr, 20);
  result_ptr += 20;

  struct evmc_result res = { EVMC_SUCCESS, msg->gas, output_data, output_size, release_result, create_address };
  memset(res.padding, 0, 4);
  return res;
}

evmc_bytes32 get_block_hash(struct evmc_host_context* context, int64_t number) {
  evmc_bytes32 block_hash{};
  int ret = csal_get_block_hash(&block_hash, number);
  if (ret != CKB_SUCCESS) {
    ckb_debug("get_block_hash failed");
  }
  return block_hash;
}

void emit_log(struct evmc_host_context* context,
              const evmc_address* address,
              const uint8_t* data,
              size_t data_size,
              const evmc_bytes32 topics[],
              size_t topics_count) {
  uint8_t buffer[2048];
  uint32_t offset = 0;
  uint32_t the_data_size = (uint32_t)data_size;
  uint32_t the_topics_count = (uint32_t)topics_count;
  size_t i;
  for (i = 0; i < sizeof(uint32_t); i++) {
    buffer[offset++] = *((uint8_t *)(&the_data_size) + i);
  }
  for (i = 0; i < data_size; i++) {
    buffer[offset++] = data[i];
  }
  for (i = 0; i < sizeof(uint32_t); i++) {
    buffer[offset++] = *((uint8_t *)(&the_topics_count) + i);
  }
  for (i = 0; i < topics_count; i++) {
    const evmc_bytes32 *topic = topics + i;
    for (size_t j = 0; j < 32; j++) {
      buffer[offset++] = topic->bytes[j];
    }
  }
  csal_log(buffer, offset);
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
  /* Do nothing */
  return 0;
}

inline void context_init(struct evmc_host_context* context,
                         struct evmc_vm *vm,
                         struct evmc_host_interface *interface,
                         evmc_address tx_origin,
                         csal_change_t *existing_values,
                         csal_change_t *changes) {
  context->existing_values = existing_values;
  context->changes = changes;
  context->tx_origin = tx_origin;
  context->destructed = false;
}

inline void return_result(const struct evmc_message *_msg, const struct evmc_result *res) {
  if (res->status_code == EVMC_SUCCESS) {
    csal_return(res->output_data, res->output_size);
  }
}

inline int verify_result(struct evmc_host_context* context,
                         const struct evmc_message *msg,
                         const struct evmc_result *res,
                         const uint8_t *return_data,
                         const size_t return_data_size,
                         const evmc_address *beneficiary) {
  /* Do nothing */
  return 0;
}
