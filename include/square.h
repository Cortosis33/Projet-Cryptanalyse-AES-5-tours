#include "utils.h"

typedef struct {
  uchar plaintext[CELLS];
  uchar ciphertext[CELLS];
} plain_cipher;

uchar GenPlaintexts(plain_cipher *pairs, uchar fix_byte, uchar others_value);

uchar EncryptPlaintexts(plain_cipher *pairs, uchar **round_keys);

void PrintAllPairs(plain_cipher *pairs);
