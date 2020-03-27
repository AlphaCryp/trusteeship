#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "bls_helper.h"


#define ARG_SIZE 82
#define PUBKEY_SIZE 41
#define G_SIZE 41
#define SIGNATURE_SIZE 21

#define BLAKE2B_BLOCK_SIZE 32
#define TEMP_SIZE 32768
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

/*
 * Arguments:
 * pubkey: 41 bytes, g: 41 bytes
 *
 * Witness:
 * WitnessArgs with a signature in lock field used to present ownership. 21 bytes
 */
int main() {
  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];
  unsigned char pubkey[PUBKEY_SIZE];
  unsigned char g[G_SIZE];

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != ARG_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(pubkey, args_bytes_seg.ptr, PUBKEY_SIZE);
  memcpy(g, args_bytes_seg.ptr + PUBKEY_SIZE * sizeof(unsigned char), G_SIZE);

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  if (lock_bytes_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  /* verify sign */
  if (bls_verify(tx_hash, BLAKE2B_BLOCK_SIZE, lock_bytes, pubkey, g) != 0) {
      return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}
