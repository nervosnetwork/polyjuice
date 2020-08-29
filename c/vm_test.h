 #include <evmc/evmc.h>

#ifdef BUILD_GENERATOR
#include "generator.h"
#else
#define CSAL_VALIDATOR_TYPE 1
#include "validator.h"
#endif

void return_result(const struct evmc_message *msg, const struct evmc_result *res);

struct evmc_host_context {
  evmc_address address;
  evmc_bytes32 key;
  evmc_bytes32 value;
  evmc_address tx_origin;
  struct evmc_host_interface *interface;
  struct evmc_vm *vm;
  bool destructed;
};

struct evmc_tx_context get_tx_context(struct evmc_host_context* context) {
  printf("[get_tx_context]");
  struct evmc_tx_context ctx{};
  ctx.tx_origin = context->tx_origin;
  return ctx;
}

bool account_exists(struct evmc_host_context* context,
                    const evmc_address* address) {
  printf("[account_exists] address: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(address->bytes+i));
  }
  printf("\n");
  return true;
}
evmc_bytes32 get_storage(struct evmc_host_context* context,
                         const evmc_address* address,
                         const evmc_bytes32* key) {
  printf("[get_storage] key: ");
  for (size_t i = 0; i < 32; i++) {
    printf("%02x", *(key->bytes+i));
  }
  printf("\n");
  evmc_bytes32 value{};
  return value;
}

enum evmc_storage_status set_storage(struct evmc_host_context* context,
                                     const evmc_address* address,
                                     const evmc_bytes32* key,
                                     const evmc_bytes32* value) {
  size_t i;
  printf("[set_storage] address: ");
  for (i = 0; i < 20; i++) {
    printf("%02x", *(address->bytes+i));
  }
  printf("\n");

  printf("[set_storage]     key: ");
  for (i = 0; i < 32; i++) {
    printf("%02x", *(key->bytes+i));
  }
  printf("\n");

  printf("[set_storage]   value: ");
  for (i = 0; i < 32; i++) {
    printf("%02x", *(value->bytes+i));
  }
  printf("\n");
  context->address = *address;
  context->key = *key;
  context->value = *value;

  return EVMC_STORAGE_ADDED;
}

size_t get_code_size(struct evmc_host_context* context,
                     const evmc_address* address) {
  printf("[get_code_size] address: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(address->bytes+i));
  }
  printf("\n");
  return 0;
}

evmc_bytes32 get_code_hash(struct evmc_host_context* context,
                           const evmc_address* address) {
  printf("[get_code_hash] address: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(address->bytes+i));
  }
  printf("\n");
  evmc_bytes32 hash{};
  return hash;
}

size_t copy_code(struct evmc_host_context* context,
                 const evmc_address* address,
                 size_t code_offset,
                 uint8_t* buffer_data,
                 size_t buffer_size) {
  printf("[copy_code] address: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(address->bytes+i));
  }
  printf("\n");
  printf("  > code_offset: %ld\n", code_offset);
  printf("  > buffer_data: 0x");
  for (size_t i = 0; i < buffer_size; i++) {
    printf("%02x", *(buffer_data+i));
  }
  printf("\n");
  return 0;
}

evmc_uint256be get_balance(struct evmc_host_context* context,
                           const evmc_address* address) {
  printf("[get_balance] address: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(address->bytes+i));
  }
  printf("\n");
  evmc_uint256be balance{};
  return balance;
}

void selfdestruct(struct evmc_host_context* context,
                       const evmc_address* address,
                       const evmc_address* beneficiary) {
  printf("[selfdestruct] beneficiary: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(beneficiary->bytes+i));
  }
  printf("\n");
}

struct evmc_result call(struct evmc_host_context* context,
                        const struct evmc_message* msg) {
  printf("[call] destination: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(msg->destination.bytes+i));
  }
  printf("\n");
  bool destructed = context->destructed;
  /* FIXME: the code_data/code_size is wrong */
  struct evmc_result res = context->vm->execute(context->vm, context->interface, context,
                                                EVMC_MAX_REVISION, msg, NULL, 0);
  printf("destructed: %s\n", context->destructed ? "true" : "false");
  context->destructed = destructed;
  return_result(msg, &res);
  return res;
}

evmc_bytes32 get_block_hash(struct evmc_host_context* context, int64_t number) {
  evmc_bytes32 block_hash{};
  return block_hash;
}

void emit_log(struct evmc_host_context* context,
              const evmc_address* address,
              const uint8_t* data,
              size_t data_size,
              const evmc_bytes32 topics[],
              size_t topics_count) {

  size_t i;

  printf("[emit_log] address: ");
  for (i = 0; i < 20; i++) {
    printf("%02x", *(address->bytes+i));
  }
  printf("\n");
  printf("[emit_log]    data: ");
  for (i = 0; i < data_size; i++) {
    printf("%02x", *(data+i));
  }
  printf("\n");

  size_t j;
  for (j = 0; j < topics_count; j++) {
    printf("[emit_log] topic[%d]: ", (int)j);
    for (i = 0; i < 32; i++) {
      printf("%02x", *(topics[j].bytes+i));
    }
    printf("\n");
  }
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
  printf("signature: ");
  for (size_t i = 0; i < 65; i++) {
    printf("%02x", *(signature_data+i));
  }
  printf("\n");
  printf("call_kind: %d\n", call_kind);
  printf("flags: %d\n", flags);
  printf("depth: %d\n", depth);
  printf("sender: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(sender->bytes+i));
  }
  printf("\n");
  printf("destination: ");
  for (size_t i = 0; i < 20; i++) {
    printf("%02x", *(destination->bytes+i));
  }
  printf("\n");
  printf("      value: ");
  for (size_t i = 0; i < 32; i++) {
    printf("%02x", *(value->bytes+i));
  }
  printf("\n");
  printf("input_size: %d\n", input_size);
  printf("input_data_ptr: %p\n", (void *)input_data);
  printf("input_data: ");
  for (size_t i = 0; i < input_size; i++) {
    printf("%02x", *(input_data+i));
  }
  printf("\n");
  printf("code_size: %d\n", code_size);
  printf("code_data: ");
  for (size_t i = 0; i < code_size; i++) {
    printf("%02x", *(code_data+i));
  }
  printf("\n");
  return 0;
}

inline void context_init(struct evmc_host_context* context,
                         struct evmc_vm *vm,
                         struct evmc_host_interface *interface,
                         const evmc_address tx_origin,
                         csal_change_t *_existing_values,
                         csal_change_t *_changes) {
  /* Do nothing */
  context->vm = vm;
  context->interface = interface;
  context->destructed = false;
}

inline void return_result(const struct evmc_message *msg, const struct evmc_result *res) {
  printf("gas_left: %ld, gas_cost: %ld\n", res->gas_left, msg->gas - res->gas_left);
  printf("output_size: %ld\n", res->output_size);
  printf("output_data: ");
  for (size_t i = 0; i < res->output_size; i++) {
    printf("%02x", *(res->output_data+i));
  }
  printf("\n");
}

inline int verify_result(struct evmc_host_context* context,
                         const struct evmc_message *msg,
                         const struct evmc_result *res,
                         const uint8_t *return_data,
                         const size_t return_data_size,
                         const evmc_address *beneficiary) {
  return 0;
}
