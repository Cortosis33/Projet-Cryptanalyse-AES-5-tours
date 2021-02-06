#include "utils.h"

#define NBR_PAIRS 256

typedef struct {
  uchar plaintext[CELLS];
  uchar ciphertext[CELLS];
  uchar ciphertext_tmp[CELLS];
} plain_cipher;

uchar GenPlaintexts(plain_cipher *pairs, uchar fix_byte, uchar others_value);

uchar EncryptPlaintexts(plain_cipher *pairs, uchar **round_keys);
