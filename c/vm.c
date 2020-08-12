#include <evmone/evmone.h>
#include <evmc/evmc.h>
#include <blake2b.h>

#ifdef BUILD_GENERATOR
#include "generator.h"
#else
#define CSAL_VALIDATOR_TYPE 1
#include "validator.h"
#endif

#define SIGNATURE_LEN 65
#define PROGRAM_LEN 4
#define CALL_KIND_LEN 1
#define FLAGS_LEN 4
#define DEPTH_LEN 4
#define ADDRESS_LEN 20
#define CALL_KIND_OFFSET (SIGNATURE_LEN + PROGRAM_LEN)
#define FLAGS_OFFSET (CALL_KIND_OFFSET + CALL_KIND_LEN)
#define DEPTH_OFFSET (FLAGS_OFFSET + FLAGS_LEN)
#define TX_ORIGIN_OFFSET (DEPTH_OFFSET + DEPTH_LEN)
#define SENDER_OFFSET (TX_ORIGIN_OFFSET + ADDRESS_LEN)
#define DESTINATION_OFFSET (SENDER_OFFSET + ADDRESS_LEN)
#define CODE_OFFSET (DESTINATION_OFFSET + ADDRESS_LEN)

#ifdef TEST_BIN
#include "vm_test.h"
#elif defined(BUILD_GENERATOR)
#include "vm_generator.h"
#else
#include "vm_validator.h"
#endif

static uint32_t global_code_size = 0;
static uint8_t *global_code_data = NULL;

/// NOTE: This program must compile use g++ since evmone implemented with c++17
int execute_vm(const uint8_t *source,
               uint32_t length,
               csal_change_t *existing_values,
               csal_change_t *changes,
               bool *destructed)
{
  const uint8_t *signature = source;
  const uint32_t program_len = *(uint32_t *)(source + SIGNATURE_LEN);
  const uint8_t call_kind = source[CALL_KIND_OFFSET];
  const uint32_t flags = *(uint32_t *)(source + FLAGS_OFFSET);
  const uint32_t depth = *(uint32_t *)(source + DEPTH_OFFSET);
  const evmc_address tx_origin = *(evmc_address *)(source + TX_ORIGIN_OFFSET);
  const evmc_address sender = *(evmc_address *)(source + SENDER_OFFSET);
  const evmc_address destination = *(evmc_address *)(source + DESTINATION_OFFSET);
  uint32_t code_size = *(uint32_t *)(source + CODE_OFFSET);
  uint8_t *code_data;
  uint32_t input_size;
  uint8_t *input_data;
  /* FIXME: handle is_inner_call */
  if (code_size > 0 || call_kind == EVMC_DELEGATECALL) {
    code_data = (uint8_t *)(source + (CODE_OFFSET + 4));
    input_size = *(uint32_t *)(code_data + code_size);
    input_data = input_size > 0 ? code_data + (code_size + 4) : NULL;

    global_code_size = code_size;
    global_code_data = code_data;
  } else {
    input_size = *(uint32_t *)(source + CODE_OFFSET + 4);
    input_data = input_size > 0 ? ((uint8_t *)source + CODE_OFFSET + 8) : NULL;

    code_size = global_code_size;
    code_data = global_code_data;
  }

  const uint8_t *other_data = source + SIGNATURE_LEN + PROGRAM_LEN + program_len;
  const uint32_t return_data_len = *(uint32_t *)other_data;
  const size_t return_data_size = (size_t)return_data_len;
  const uint8_t *return_data = other_data + 4;
  const evmc_address beneficiary = *(evmc_address *)(return_data + return_data_size);

  int ret = verify_params(signature, call_kind, flags, depth, &tx_origin, &sender, &destination,
                          code_size, code_data, input_size, input_data);
#ifdef CSAL_VALIDATOR_TYPE
  debug_print_int("verify params", ret);
#endif
  if (ret != 0) {
    return ret;
  }

  struct evmc_vm *vm = evmc_create_evmone();
  struct evmc_host_interface interface = { account_exists, get_storage, set_storage, get_balance, get_code_size, get_code_hash, copy_code, selfdestruct, call, get_tx_context, get_block_hash, emit_log};
  struct evmc_host_context context;
  context_init(&context, vm, &interface, tx_origin, existing_values, changes);

  struct evmc_message msg;
  msg.kind = (evmc_call_kind) call_kind;
  msg.flags = flags;
  msg.depth = depth;
  msg.gas = 10000000;
  msg.destination = destination;
  msg.sender = sender;
  msg.input_data = input_data;
  msg.input_size = input_size;
  msg.value = evmc_uint256be{};
  msg.create2_salt = evmc_bytes32{};

  struct evmc_result res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, &msg, code_data, code_size);
  *destructed = context.destructed;
  return_result(&msg, &res);
  ret = verify_result(&context, &msg, &res, return_data, return_data_size, &beneficiary);
#ifdef CSAL_VALIDATOR_TYPE
  debug_print_int("verify result", ret);
#endif
  if (ret != 0) {
    return ret;
  }

  if (msg.kind == EVMC_CREATE) {
    global_code_size = res.output_size;
    global_code_data = (uint8_t *)res.output_data;
  }

#ifdef CSAL_VALIDATOR_TYPE
  debug_print_int("return status_code", res.status_code);
#endif
  return (int)res.status_code;
}
