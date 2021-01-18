#include "square.h"

/*
fonction permettant de creer le tableau des plaintexts
*/
uchar GenPlaintexts(plain_cipher *pairs, uchar fix_byte, uchar others_value) {

  if (fix_byte >= 16) {
    return EXIT_FAILURE;
  }

  for (uchar i = 0; i < 255; i++) {

    // on remplie de plaintext de 0
    for (size_t j = 0; j < 16; j++) {
      pairs[i].plaintext[j] = others_value;
      // on initilise aussi le text chiffré avec le text clair
      pairs[i].ciphertext[j] = others_value;
    }

    // on fait varier l'octet identifié par fix_byte
    // on varie de 1 à 255 pour ne pas avoir de valeurs nulles (d'ou le +1)
    // soit de 0 à 254
    pairs[i].plaintext[fix_byte] = i + 1;
    pairs[i].ciphertext[fix_byte] = i + 1;
  }

  return EXIT_SUCCESS;
}

/*
fonction permettant de chiffrer le clair de la structure plain_cipher
*/
uchar EncryptPlaintexts(plain_cipher *pairs, uchar **round_keys) {
  for (size_t i = 0; i < 255; i++) {
    // on chiffre ciphertext qui est initialisé avec le clair
    Encryption(pairs[i].ciphertext, round_keys);
  }

  return EXIT_SUCCESS;
}

void PrintAllPairs(plain_cipher *pairs) {
  for (size_t i = 0; i < 255; i++) {
    fprintf(stdout, "%zu\n", i);
    PrintByteArray(pairs[i].plaintext, CELLS, (const uchar *)"Plaintext");
    PrintByteArray(pairs[i].ciphertext, CELLS, (const uchar *)"CipherText");
  }
}
