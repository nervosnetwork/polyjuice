/*
 * Basic skeleton for CKB generator part of the account layer design. To reduce
 * integration efforts as much as possible, the core of the generator code is
 * also organized as a script running on CKB VM. The result of this, is that the
 * developer only needs to provide the actual VM implementation that is runnable
 * on CKB VM, the same VM implementation will be compiled and linked into a
 * generator script, and a validator script, both of which are executed on CKB
 * VM instances. The difference here, is that the VM instances running generator
 * script has customized syscalls that support generator behavior.
 */
#ifndef CSAL_SMT_GENERATOR_H_
#define CSAL_SMT_GENERATOR_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CSAL_KEY_BYTES 32
#define CSAL_VALUE_BYTES 32

typedef void *csal_change_t;

int csal_change_insert(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                       const uint8_t value[CSAL_VALUE_BYTES]);
int csal_change_fetch(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                      uint8_t value[CSAL_VALUE_BYTES]);

/* See validator.h for explanations on execute_vm */
extern int execute_vm(const uint8_t *source,
                      uint32_t length,
                      csal_change_t *existing_values,
                      csal_change_t *changes,
                      bool *destructed);

#include <ckb_syscalls.h>

#ifdef TEST_BIN
#include <stdio.h>
#endif

int main(int argc, char *argv[]) {
  if (argc != 3) {
    ckb_debug(
        "Usage: generator <executed program length in 32-bit unsigned little "
        "endian integer> <executed program>");
    return -1;
  }

#ifdef TEST_BIN
  const char *length_hex = argv[1];
  const char *binary_hex = argv[2];

  /* 100KB */
  char buffer[100 * 1024];
  char part1;
  char part2;
  for (size_t i = 0; i < 4; i++) {
    part1 = length_hex[i*2];
    part2 = length_hex[i*2 + 1];
    part1 = part1 >= 'a' ? (part1 - 'a' + 10) : (part1 - '0');
    part2 = part2 >= 'a' ? (part2 - 'a' + 10) : (part2 - '0');
    buffer[i] = part1 * 16 + part2;
  }
  uint32_t length = *((uint32_t *)buffer);
  printf("program len: %d\n", length);

  for (size_t i = 0; i < length; i++) {
    part1 = binary_hex[i*2];
    part2 = binary_hex[i*2 + 1];
    part1 = part1 >= 'a' ? (part1 - 'a' + 10) : (part1 - '0');
    part2 = part2 >= 'a' ? (part2 - 'a' + 10) : (part2 - '0');
    buffer[i] = part1 * 16 + part2;
  }
  const uint8_t *source = (const uint8_t *)buffer;
#else
  uint32_t length = *((uint32_t *)argv[1]);
  const uint8_t *source = (const uint8_t *)argv[2];
#endif

  /* Generator don't need any setup for now, the actual APIs will be implemented
   * via syscalls */
  csal_change_t existing_values = NULL;
  csal_change_t changes = NULL;
  bool destructed;
  return execute_vm(source, length, &existing_values, &changes, &destructed);
}

#define _CSAL_CHANGE_INSERT_SYSCALL_NUMBER 3073
#define _CSAL_CHANGE_FETCH_SYSCALL_NUMBER 3074

int csal_change_insert(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                       const uint8_t value[CSAL_VALUE_BYTES]) {
  return syscall(_CSAL_CHANGE_INSERT_SYSCALL_NUMBER, key, value, 0, 0, 0, 0);
}
int csal_change_fetch(csal_change_t *state, const uint8_t key[CSAL_KEY_BYTES],
                      uint8_t value[CSAL_VALUE_BYTES]) {
  return syscall(_CSAL_CHANGE_FETCH_SYSCALL_NUMBER, key, value, 0, 0, 0, 0);
}

#endif /* CSAL_SMT_GENERATOR_H_ */
