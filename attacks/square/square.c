#include "square.h"

/*
fonction epermettant de creer le tableau des plaintexts
*/
uchar create_plaintexts(plain_cipher *pairs, uchar fix_byte) {

  for (uchar i = 0; i < 255; i++) {

    // on remplie de plaintext de 0
    for (size_t j = 0; j < 16; j++) {
      pairs[i].plaintext[j] = 0;
    }

    // on fait varier l'octet identifié par fix_byte
    // on varie de 1 à 255 pour ne pas avoir de valeurs nuls (d'ou le +1)
    pairs[i].plaintext[fix_byte] = i + 1;
  }

  return EXIT_SUCCESS;
}

void print_all_plaintexts(plain_cipher *pairs) {
  for (size_t i = 0; i < 255; i++) {
    fprintf(stdout, "%zu\n", i);
    PrintByteArray(pairs[i].plaintext, CELLS, (const uchar *)"Plaintext");
  }
}
