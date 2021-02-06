#include "../../include/square.h"

void PrintAllPairs(plain_cipher *pairs) {
  for (size_t i = 0; i < NBR_PAIRS; i++) {
    fprintf(stdout, "%zu\n", i);
    PrintByteArray(pairs[i].plaintext, CELLS, (const uchar *)"Plaintext");
    PrintByteArray(pairs[i].ciphertext, CELLS, (const uchar *)"CipherText");
  }
}
