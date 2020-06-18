#ifndef CSAL_VALIDATOR_UTILS_H_
#define CSAL_VALIDATOR_UTILS_H_

#include <blake2b.h>
#include <molecule/blockchain.h>
#include <ckb_syscalls.h>

int csal_check_type_id() {
  uint8_t script[128];
  uint64_t len = 128;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > 128) {
    return CSAL_ERROR_BUFFER_NOT_LARGE_ENOUGH;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return CSAL_ERROR_INVALID_TYPE_ID;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != 32) {
    return CSAL_ERROR_INVALID_TYPE_ID;
  }

  uint8_t input[128];
  len = 128;
  ret = ckb_load_input(input, &len, 0, 0, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > 128) {
    return CSAL_ERROR_BUFFER_NOT_LARGE_ENOUGH;
  }

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, input, len);
  /* TODO: hash current output position as well */
  uint8_t hash[32];
  blake2b_final(&blake2b_ctx, hash, 32);
  if (memcmp(args_bytes_seg.ptr, hash, 32) != 0) {
    return CSAL_ERROR_INVALID_TYPE_ID;
  }

  return CKB_SUCCESS;
}

#endif /* CSAL_VALIDATOR_UTILS_H_ */
