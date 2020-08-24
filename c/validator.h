/*
 * A basic skeleton for a CKB validator script for an account based design.
 * Working together with the surrounding generator skeleton, it provides an
 * account/state model based abstraction on top of Nervos CKB:
 *
 * * An off-chain generator keeps track of account layer storage, while
 * preparing transactions on Nervos CKB based on state based VM execution.
 * * An on-chain validator script(the underlying source file) validates the
 * same VM logic on-chain, ensuring all state updates are valid following
 * execution rules
 *
 * To save on-chain storage as much as possible(storage is expensive!), this
 * implementation leverages Sparse Merkle Tree to save space. Only a single
 * hash value is stored on-chain, keeping a constant space requirement no
 * matter how large the storage space is needed. A separate implementation
 * that keeps all storage on-chain might be provided later if needed.
 *
 * The skeleton is also designed to work with any possible VMs, which includes
 * but is not limited to:
 *
 * 1. JavaScript VM
 * 2. Bitcoin-like Forth VM
 * 3. EVM
 * 4. Move VM
 * 5. etc.
 *
 * We will provide some of those to support an out-of-the-box usage, but you
 * are also free to integrate this with whatever VMs you like.
 */
#ifndef CSAL_SMT_VALIDATOR_H_
#define CSAL_SMT_VALIDATOR_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <ckb_syscalls.h>

#define CSAL_ERROR_INSUFFICIENT_CAPACITY -20
#define CSAL_ERROR_NOT_FOUND             -21
#define CSAL_ERROR_INVALID_TYPE_ID       -22

#define CSAL_SCRIPT_ARGS_LEN 20
#define CSAL_KEY_BYTES 32
#define CSAL_VALUE_BYTES 32

typedef struct {
  uint8_t key[CSAL_KEY_BYTES];
  uint8_t value[CSAL_VALUE_BYTES];
  uint64_t order;
} csal_entry_t;

typedef struct {
  csal_entry_t *entries;
  uint32_t length;
  uint32_t capacity;
} csal_change_t;

void csal_change_init(csal_change_t *state, csal_entry_t *buffer,
                      uint32_t capacity);
int csal_change_insert(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                       const uint8_t value[CSAL_VALUE_BYTES]);
int csal_change_fetch(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                      uint8_t value[CSAL_VALUE_BYTES]);
void csal_change_organize(csal_change_t *state);

#ifdef NO_DEBUG_LOG
#define debug_print(s)
#define debug_print_int(prefix, value)
#define debug_print_data(prefix, data, data_len)
#else  /* #ifdef NO_DEBUG_LOG */
#define debug_print(s)                            ckb_debug(s)
#define debug_print_int(prefix, value)            debug_print_int_impl((prefix), (value))
#define debug_print_data(prefix, data, data_len)  debug_print_data_impl((prefix), (data), (data_len))

#ifdef LONG_DEBUG_LOG
static char debug_buffer[64 * 1024];
static void debug_print_data_impl(const char *prefix,
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
static void debug_print_int_impl(const char *prefix, int ret) {
  sprintf(debug_buffer, "%s => %d", prefix, ret);
  ckb_debug(debug_buffer);
}
#else  /* #ifdef LONG_DEBUG_LOG */
static char debug_buffer[1024];
static void debug_print_data_impl(const char *prefix, const uint8_t *data, uint32_t data_len) {
  if (strlen(prefix) + data_len * 2 + 3 > 120) {
    ckb_debug(prefix);
    ckb_debug("...... <data too long> ......");
  } else {
    int offset = 0;
    offset += sprintf(debug_buffer, "%s 0x", prefix);
    for (size_t i = 0; i < data_len; i++) {
      offset += sprintf(debug_buffer + offset, "%02x", data[i]);
    }
    debug_buffer[offset] = '\0';
    ckb_debug(debug_buffer);
  }
}
static void debug_print_int_impl(const char *prefix, int ret) {
  sprintf(debug_buffer, "%s => %d", prefix, ret);
  ckb_debug(debug_buffer);
}
#endif  /* #ifdef LONG_DEBUG_LOG */

#endif  /* #ifdef NO_DEBUG_LOG */


#ifndef CSAL_NO_IMPLEMENTATION
void csal_change_init(csal_change_t *state, csal_entry_t *buffer,
                      uint32_t capacity) {
  state->entries = buffer;
  state->length = 0;
  state->capacity = capacity;
}

int csal_change_insert(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                       const uint8_t value[CSAL_VALUE_BYTES]) {
  /*
  if (state->length < state->capacity) {
    // Shortcut, append at last
    memcpy(state->entries[state->length].key, key, CSAL_KEY_BYTES);
    memcpy(state->entries[state->length].value, value, CSAL_VALUE_BYTES);
    state->length++;
    return 0;
  }
  */
  /* Find the last matching key, and overwrites it */
  int32_t i = state->length - 1;
  for (; i >= 0; i--) {
    if (memcmp(key, state->entries[i].key, CSAL_KEY_BYTES) == 0) {
      break;
    }
  }
  if (i < 0) {
    /* No matching key found, we are running out of capacity */
    memcpy(state->entries[state->length].key, key, CSAL_VALUE_BYTES);
    memcpy(state->entries[state->length].value, value, CSAL_VALUE_BYTES);
    state->length++;
  } else {
    memcpy(state->entries[i].value, value, CSAL_VALUE_BYTES);
  }
  return 0;
}

int csal_change_fetch(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                      uint8_t value[CSAL_VALUE_BYTES]) {
  int32_t i = state->length - 1;
  for (; i >= 0; i--) {
    if (memcmp(key, state->entries[i].key, CSAL_KEY_BYTES) == 0) {
      memcpy(value, state->entries[i].value, CSAL_VALUE_BYTES);
      return 0;
    }
  }
  return CSAL_ERROR_NOT_FOUND;
}

int _csal_entry_cmp(const void *a, const void *b) {
  const csal_entry_t *ea = (const csal_entry_t *)a;
  const csal_entry_t *eb = (const csal_entry_t *)b;

  for (int i = CSAL_KEY_BYTES - 1; i >= 0; i--) {
    int cmp_result = ea->key[i] - eb->key[i];
    if (cmp_result != 0) {
      return cmp_result;
    }
  }
  return 0;
}

void csal_change_organize(csal_change_t *state) {
  /*
  for (uint32_t i = 0; i < state->length; i++) {
    state->entries[i].order = i;
  }
  */
  qsort(state->entries, state->length, sizeof(csal_entry_t), _csal_entry_cmp);
  /* Remove duplicate ones */
  /*
  int32_t sorted = 0, next = 0;
  while ((uint32_t)next < state->length) {
    int32_t item_index = next++;
    while ((uint32_t)next < state->length &&
           memcmp(state->entries[item_index].key, state->entries[next].key,
                  CSAL_KEY_BYTES) == 0) {
      next++;
    }
    if (item_index != sorted) {
      memcpy(state->entries[sorted].key, state->entries[item_index].key,
             CSAL_KEY_BYTES);
      memcpy(state->entries[sorted].value, state->entries[item_index].value,
             CSAL_VALUE_BYTES);
    }
    sorted++;
  }
  state->length = sorted;
  */
}
#endif /* CSAL_NO_IMPLEMENTATION */

#define CSAL_VALIDATOR_TYPE_SMT 1
#define CSAL_VALIDATOR_TYPE_FULLSTORAGE 2

#if (CSAL_VALIDATOR_TYPE == CSAL_VALIDATOR_TYPE_SMT)
#include <blake2b.h>

#if (CSAL_KEY_BYTES != 32)
#error "SMT solution only works with 256 bit keys!"
#endif

#define CSAL_ERROR_INVALID_PROOF_LENGTH -30
#define CSAL_ERROR_INVALID_PROOF        -31
#define CSAL_ERROR_INVALID_STACK        -32
#define CSAL_ERROR_INVALID_SIBLING      -33

int csal_smt_update_root(uint8_t buffer[32], const csal_change_t *pairs,
                         const uint8_t *proof, uint32_t proof_length);
int csal_smt_verify(const uint8_t hash[32], const csal_change_t *pairs,
                    const uint8_t *proof, uint32_t proof_length);

#ifndef CSAL_NO_IMPLEMENTATION
int _csal_get_bit(const uint8_t *data, int offset) {
  int byte_pos = offset / 8;
  int bit_pos = offset % 8;
  return ((data[byte_pos] >> bit_pos) & 1) != 0;
}

void _csal_set_bit(uint8_t *data, int offset) {
  int byte_pos = offset / 8;
  int bit_pos = offset % 8;
  data[byte_pos] |= 1 << bit_pos;
}

void _csal_clear_bit(uint8_t *data, int offset) {
  int byte_pos = offset / 8;
  int bit_pos = offset % 8;
  data[byte_pos] &= (uint8_t)(~(1 << bit_pos));
}

void _csal_copy_bits(uint8_t source[32], int first_kept_bit) {
  int first_byte = first_kept_bit / 8;
  for (int i = 0; i < first_byte; i++) {
    source[i] = 0;
  }
  for (int i = first_byte * 8; i < first_kept_bit; i++) {
    _csal_clear_bit(source, i);
  }
}

void _csal_parent_path(uint8_t key[32], uint8_t height) {
  if (height == 255) {
    memset(key, 0, 32);
  } else {
    _csal_copy_bits(key, height + 1);
  }
}
void _csal_merge(blake2b_state *blake2b_ctx,
                 const uint8_t zero_value[32],
                 const uint8_t lhs[32],
                 const uint8_t rhs[32],
                 uint8_t output[32]) {
  if (memcmp(lhs, zero_value, 32) == 0) {
    memcpy(output, rhs, 32);
  } else if (memcmp(rhs, zero_value, 32) == 0) {
    memcpy(output, lhs, 32);
  } else {
    blake2b_init(blake2b_ctx, 32);
    blake2b_update(blake2b_ctx, lhs, 32);
    blake2b_update(blake2b_ctx, rhs, 32);
    blake2b_final(blake2b_ctx, output, 32);
  }
}

/*
 * Theoretically, a stack size of x should be able to process as many as
 * 2 ** (x - 1) updates. In this case with a stack size of 32, we can deal
 * with 2 ** 31 == 2147483648 updates, which is more than enough.
 */
#define _CSAL_SMT_STACK_SIZE 32

int csal_smt_update_root(uint8_t buffer[32], const csal_change_t *pairs,
                         const uint8_t *proof, uint32_t proof_length) {
  uint8_t zero_value[CSAL_VALUE_BYTES];
  memset(zero_value, 0, CSAL_VALUE_BYTES);

  blake2b_state blake2b_ctx;
  uint8_t stack_keys[_CSAL_SMT_STACK_SIZE][CSAL_KEY_BYTES];
  uint8_t stack_values[_CSAL_SMT_STACK_SIZE][32];
  uint32_t proof_index = 0;
  uint32_t leave_index = 0;
  uint32_t stack_top = 0;

  while (proof_index < proof_length) {
    switch (proof[proof_index++]) {
      case 0x4C:
        if (stack_top >= _CSAL_SMT_STACK_SIZE) {
          return CSAL_ERROR_INVALID_STACK;
        }
        if (leave_index >= pairs->length) {
          return CSAL_ERROR_INVALID_PROOF;
        }
        memcpy(stack_keys[stack_top], pairs->entries[leave_index].key, CSAL_KEY_BYTES);
        if (memcmp(pairs->entries[leave_index].value, zero_value, 32) == 0) {
          memcpy(stack_values[stack_top], zero_value, 32);
        } else {
          blake2b_init(&blake2b_ctx, 32);
          blake2b_update(&blake2b_ctx, pairs->entries[leave_index].key, CSAL_KEY_BYTES);
          blake2b_update(&blake2b_ctx, pairs->entries[leave_index].value, CSAL_VALUE_BYTES);
          blake2b_final(&blake2b_ctx, stack_values[stack_top], 32);
        }
        stack_top++;
        leave_index++;
        break;
      case 0x50: {
        if (stack_top == 0) {
          return CSAL_ERROR_INVALID_STACK;
        }
        if (proof_index + 33 > proof_length) {
          return CSAL_ERROR_INVALID_PROOF;
        }
        uint8_t height = proof[proof_index++];
        const uint8_t *current_proof = &proof[proof_index];
        proof_index += 32;
        uint8_t *key = stack_keys[stack_top - 1];
        uint8_t *value = stack_values[stack_top - 1];
        if (_csal_get_bit(key, height)) {
          _csal_merge(&blake2b_ctx, zero_value, current_proof, value, value);
        } else {
          _csal_merge(&blake2b_ctx, zero_value, value, current_proof, value);
        }
        _csal_parent_path(key, height);
      } break;
      case 0x48: {
        if (stack_top < 2) {
          return CSAL_ERROR_INVALID_STACK;
        }
        if (proof_index >= proof_length) {
          return CSAL_ERROR_INVALID_PROOF;
        }
        uint8_t height = proof[proof_index++];
        uint8_t *key_a = stack_keys[stack_top - 2];
        uint8_t *value_a = stack_values[stack_top - 2];
        uint8_t *key_b = stack_keys[stack_top - 1];
        uint8_t *value_b = stack_values[stack_top - 1];
        stack_top -= 2;
        int a_set = _csal_get_bit(key_a, height);
        int b_set = _csal_get_bit(key_b, height);
        _csal_copy_bits(key_a, height);
        _csal_copy_bits(key_b, height);
        uint8_t sibling_key_a[32];
        memcpy(sibling_key_a, key_a, 32);
        if (!a_set) {
          _csal_set_bit(sibling_key_a, height);
        }
        if (memcmp(sibling_key_a, key_b, 32) != 0 || (a_set == b_set)) {
          return CSAL_ERROR_INVALID_SIBLING;
        }
        /* Top-of-stack key is already updated to parent_key_a */
        if (a_set) {
          _csal_merge(&blake2b_ctx, zero_value, value_b, value_a, value_a);
        } else {
          _csal_merge(&blake2b_ctx, zero_value, value_a, value_b, value_a);
        }
        stack_top++;
      } break;
      default:
        return CSAL_ERROR_INVALID_PROOF;
    }
  }
  /* All leaves must be used */
  if (leave_index != pairs->length) {
    return CSAL_ERROR_INVALID_PROOF;
  }
  if (stack_top != 1) {
    return CSAL_ERROR_INVALID_STACK;
  }
  memcpy(buffer, stack_values[0], 32);
  return 0;
}

int csal_smt_verify(const uint8_t hash[32], const csal_change_t *pairs,
                    const uint8_t *proof, uint32_t proof_length) {
  uint8_t buffer[32];
  int ret = csal_smt_update_root(buffer, pairs, proof, proof_length);
  if (ret != 0) {
    return ret;
  }
  if (memcmp(buffer, hash, 32) != 0) {
    return CSAL_ERROR_INVALID_PROOF;
  }
  return 0;
}

#endif /* CSAL_NO_IMPLEMENTATION */

#else
#error "Invalid CSAL validator type!"
#endif /* CSAL_VALIDATOR_TYPE */

#ifndef CSAL_NO_VALIDATOR_SKELETON
#include <molecule/blockchain.h>
#include <ckb_syscalls.h>

/*
 * This function abstracts out the exact account model VM to use.
 *
 * The validator code needs to be linked together with a VM implemenation
 * exposed via +execute_vm+ function. Note it doesn't matter what VM is used
 * here, such as a dummy one, a JavaScript VM, a Bitcoin-like Forth VM, even
 * EVM or Move VM can be integrated here. The validator here will then invoke
 * the VM with the following expectations:
 *
 * 1. The actual on-chain storage will be modeled as a key-value store.
 * 2. All the values that will be read when executing the VM are provided in
 * +existing_values+. If the program tries to read from a key that is not
 * expected in the VM, a return value of all zeros should be used.
 * 3. The VM should record all writes from the VM in +changes+ using the exact
 * same order as each write happens. If you are operating on +changes+ using
 * the provided +csal_change_insert+, this will be automatically ensured. When
 * +csal_change_insert+ returns with a non-zero value, the VM should also halt
 * with the same return value.
 * 4. +existing_values+ can be updated however one wants to cope with write
 * updates, this will not be used by the validator skeleton after VM finishes
 * execution.
 * 5. When the VM finishes execution, a zero value should be returned.
 * 6. The surrounding validator environment will operate only with stack memory,
 * meaning the VM is free to use heap space as it requires.
 */
extern int execute_vm(const uint8_t *source,
                      uint32_t length,
                      csal_change_t *existing_values,
                      csal_change_t *changes,
                      bool *destructed);

#define MAXIMUM_READS 1024
#define MAXIMUM_WRITES 1024
#define SCRIPT_SIZE 128
#define INPUT_SIZE 44
#define WITNESS_SIZE (300 * 1024)

#define ERROR_BUFFER_NOT_ENOUGH    -50
#define ERROR_INVALID_DATA         -51
#define ERROR_EOF                  -52
#define ERROR_TOO_MANY_CHANGES     -53
#define ERROR_UNSUPPORED_FLAGS     -54
#define ERROR_INVALID_ROOT_HASH    -55
#define ERROR_DESTRUCT_WITH_OUTPUT -56

#define UNUSED_FLAGS 0xfffffffffffffffe

#define FLAG_WITNESS_LOCATION 0x1
#define FLAG_WITNESS_LOCATION_LOCK 0x0
#define FLAG_WITNESS_LOCATION_TYPE 0x1

typedef struct {
  uint8_t *ptr;
  uint32_t size;
  uint32_t offset;
} reader_t;

void reader_init(reader_t *reader, uint8_t *ptr, uint32_t size) {
  reader->ptr = ptr;
  reader->size = size;
  reader->offset = 0;
}

int reader_bytes(reader_t *reader, uint32_t size, uint8_t **out) {
  if (reader->size - reader->offset < size) {
    return ERROR_EOF;
  }
  if (out != NULL) {
    *out = &reader->ptr[reader->offset];
  }
  reader->offset += size;
  return CKB_SUCCESS;
}

int reader_uint32(reader_t *reader, uint32_t *out) {
  uint8_t *p = NULL;
  int ret = reader_bytes(reader, 4, &p);
  if (ret != 0) {
    return ret;
  }
  if (out != NULL) {
    *out = *((uint32_t *)p);
  }
  return CKB_SUCCESS;
}


int main() {
  /* Load script.args to check type id logic
   */
  uint8_t script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_checked_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_INVALID_DATA;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != CSAL_SCRIPT_ARGS_LEN) {
    return ERROR_INVALID_DATA;
  }

  size_t index = 0;
  int input_index = -1;
  uint8_t type_script[SCRIPT_SIZE];
  while (1) {
    len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(type_script, &len, 0, index, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (script_seg.size == len && memcmp(script_seg.ptr, type_script, len) == 0) {
      if (input_index > -1) {
        return CSAL_ERROR_INVALID_TYPE_ID;
      } else {
        input_index = (int)index;
      }
    }
    index += 1;
  }

  int output_index = -1;
  index = 0;
  while (1) {
    len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(type_script, &len, 0, index, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (script_seg.size == len && memcmp(script_seg.ptr, type_script, len) == 0) {
      if (output_index > -1) {
        return CSAL_ERROR_INVALID_TYPE_ID;
      } else {
        output_index = (int)index;
      }
    }
    index += 1;
  }

  debug_print_int("input_index:", input_index);
  debug_print_int("output_index:", output_index);

  // Create
  if (input_index == -1 && output_index > -1) {
    debug_print("create contract");

    uint8_t first_input[INPUT_SIZE];
    len = INPUT_SIZE;
    ret = ckb_load_input(first_input, &len, 0, 0, CKB_SOURCE_INPUT);
    uint64_t first_output_index = (uint64_t) output_index;

    uint8_t hash[32];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, 32);
    blake2b_update(&blake2b_ctx, first_input, len);
    blake2b_update(&blake2b_ctx, ((const void *)(&first_output_index)), 8);
    blake2b_final(&blake2b_ctx, hash, 32);
    if (memcmp(args_bytes_seg.ptr, hash, CSAL_SCRIPT_ARGS_LEN) != 0) {
      return CSAL_ERROR_INVALID_TYPE_ID;
    }
  }
  // Destroy => if (input_index > -1 && output_index == -1) {}

  /*
   * Witness shall contain the content used for validating account state change.
   * Depending on different flags and transaction structure, the witness will be
   * located in different parts of witness.
   */
  uint8_t witness[WITNESS_SIZE];
  len = WITNESS_SIZE;
  size_t cell_source = 0;
  // TODO: support contract call contract
  ret = ckb_load_actual_type_witness(witness, &len, 0, &cell_source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  mol_seg_t witness_seg;
  witness_seg.ptr = (uint8_t *)witness;
  witness_seg.size = len;
  debug_print_int("load witness:", (int) witness_seg.size);
  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_INVALID_DATA;
  }
  mol_seg_t content_seg;
  if (cell_source == CKB_SOURCE_GROUP_OUTPUT) {
    content_seg = MolReader_WitnessArgs_get_output_type(&witness_seg);
  } else {
    content_seg = MolReader_WitnessArgs_get_input_type(&witness_seg);
  }
  if (MolReader_BytesOpt_is_none(&content_seg)) {
    return ERROR_INVALID_DATA;
  }
  mol_seg_t content_bytes_seg = MolReader_Bytes_raw_bytes(&content_seg);
  reader_t content_reader;
  reader_init(&content_reader, content_bytes_seg.ptr, content_bytes_seg.size);

  /*
   * Load input & output root hash
   */
  uint8_t input_root_hash[32];
  len = 32;
  ret = ckb_load_cell_data(input_root_hash, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret == CKB_INDEX_OUT_OF_BOUND) {
    /* Initial creation */
    memset(input_root_hash, 0, 32);
  } else {
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len < 32) {
      return ERROR_INVALID_DATA;
    }
  }
  debug_print_data(" input root:", input_root_hash, 32);

  /*
   * Parse VM source, read values, read proofs from witness content part.
   * Read proofs are validated on the fly.
   */
  debug_print_data(">> raw witness", content_reader.ptr, content_reader.size);
  debug_print_int(">> content_reader.size", content_reader.size);
  bool destructed = false;
  while(1) {
    uint32_t source_length = 0;
    ret = reader_uint32(&content_reader, &source_length);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    /* The end of program */
    debug_print_int(">> source_length", source_length);
    debug_print_int(">> content_reader.offset", content_reader.offset);
    if (source_length == 0) {
      break;
    }
    if (destructed) {
      /* TODO: error code */
      return -234;
    }

    uint8_t *source = NULL;
    ret = reader_bytes(&content_reader, source_length, &source);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    debug_print_data("source:", source, source_length);

    csal_entry_t read_entries[MAXIMUM_READS];
    csal_change_t read_changes;
    csal_change_init(&read_changes, read_entries, MAXIMUM_READS);
    debug_print_int("csal_change_init(&read_changes);", 0);
    uint32_t reads = 0;
    ret = reader_uint32(&content_reader, &reads);
    debug_print_int(">> reads", reads);
    debug_print_int(">> content_reader.offset", content_reader.offset);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (reads > MAXIMUM_READS) {
      return ERROR_TOO_MANY_CHANGES;
    }
    for (uint32_t i = 0; i < reads; i++) {
      uint8_t *key = NULL, *value = NULL;
      ret = reader_bytes(&content_reader, CSAL_KEY_BYTES, &key);
      debug_print_int(">> content_reader.offset", content_reader.offset);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      ret = reader_bytes(&content_reader, CSAL_VALUE_BYTES, &value);
      debug_print_int(">> content_reader.offset", content_reader.offset);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      ret = csal_change_insert(&read_changes, key, value);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
    uint8_t *proof = NULL;
    uint32_t proof_size = 0;
    ret = reader_uint32(&content_reader, &proof_size);
    debug_print_int(">> proof_size", proof_size);
    debug_print_int(">> content_reader.offset", content_reader.offset);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = reader_bytes(&content_reader, proof_size, &proof);
    debug_print_data("read proof:", proof, proof_size);
    if (ret != CKB_SUCCESS) {
      return ret;
    }

    if (proof_size > 0) {
      csal_change_organize(&read_changes);
      ret = csal_smt_verify(input_root_hash, &read_changes, proof, proof_size);
      debug_print_int("csal_smt_verify(input_root_hash);", ret);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    } else if (read_changes.length != 0) {
      return CSAL_ERROR_INVALID_PROOF;
    }

    /* Now let's execute the VM. */
    csal_entry_t write_entries[MAXIMUM_WRITES];
    csal_change_t write_changes;
    csal_change_init(&write_changes, write_entries, MAXIMUM_WRITES);
    debug_print_int("csal_change_init(&write_changes);", 0);

    debug_print("execute_vm() start");
    ret = execute_vm(source, source_length, &read_changes, &write_changes, &destructed);
    debug_print_int("execute_vm()", ret);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    csal_change_organize(&write_changes);

    /*
     * First, read old values of changed keys, since we already validated
     * read values, we can reuse read_changes.
     */
    csal_change_init(&read_changes, read_entries, MAXIMUM_READS);
    debug_print("csal_change_init(&read_changes, read_entries, MAXIMUM_READS) end");
    uint32_t write_changes_len;
    ret = reader_uint32(&content_reader, &write_changes_len);
    debug_print("reader_uint32(&content_reader, &write_changes_len) end");
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    debug_print_int("write_changes.length:", write_changes.length);
    debug_print_int("write_changes_len:", write_changes_len);
    if (write_changes_len != write_changes.length) {
      return -111;
    }
    for (uint32_t i = 0; i < write_changes.length; i++) {
      uint8_t *old_value = NULL;
      ret = reader_bytes(&content_reader, CSAL_VALUE_BYTES, &old_value);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      ret = csal_change_insert(&read_changes, write_changes.entries[i].key,
                               old_value);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }

    /* Now let's read the proof for old values, and verify them */
    proof = NULL;
    proof_size = 0;
    ret = reader_uint32(&content_reader, &proof_size);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = reader_bytes(&content_reader, proof_size, &proof);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    debug_print_data("write old proof:", proof, proof_size);
    if (proof_size > 0) {
      csal_change_organize(&read_changes);
      ret = csal_smt_verify(input_root_hash, &read_changes, proof, proof_size);
      debug_print_int("csal_smt_verify(input_root_hash, &read_changes);", ret);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    } else if (read_changes.length != 0) {
      return CSAL_ERROR_INVALID_PROOF;
    }
    /*
     * Now that we have a valid proof, we use it to generate new root hash
     * using wrtie_changes
     */
    if (proof_size > 0) {
      csal_change_organize(&write_changes);
      ret = csal_smt_update_root(input_root_hash, &write_changes, proof, proof_size);
      debug_print_int("csal_smt_update_root(input_root_hash, &write_changes);", ret);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  }

  uint8_t output_root_hash[32];
  len = 32;
  ret =
    ckb_load_cell_data(output_root_hash, &len, 0, 0, CKB_SOURCE_GROUP_OUTPUT);
  if (ret != CKB_INDEX_OUT_OF_BOUND && destructed) {
    debug_print("destructed contract can not have output in the same group");
    return ERROR_DESTRUCT_WITH_OUTPUT;
  }
  if (ret == CKB_INDEX_OUT_OF_BOUND && destructed) {
    /* This is a special mode for destorying cells */
    debug_print("contract destructed");
    return CKB_SUCCESS;
  }
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len < 32) {
    return ERROR_INVALID_DATA;
  }
  debug_print_data("input root:", input_root_hash, 32);
  debug_print_data("output root:", output_root_hash, 32);

  if (memcmp(input_root_hash, output_root_hash, 32) != 0) {
    return ERROR_INVALID_ROOT_HASH;
  }

  return CKB_SUCCESS;
}
#endif /* CSAL_NO_VALIDATOR_SKELETON */

#endif /* CSAL_SMT_VALIDATOR_H_ */
