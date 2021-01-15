#include "utils.h"

typedef struct {
  uchar plaintext[CELLS];
  uchar ciphertext[CELLS];
} plain_cipher;

uchar create_plaintexts(plain_cipher *pairs, uchar fix_byte);

void print_all_plaintexts(plain_cipher *pairs);
