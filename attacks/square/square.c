#include "../../include/square.h"

/*
fonction permettant de creer le tableau des plaintexts
*/
uchar GenPlaintexts(plain_cipher *pairs, uchar fix_byte, uchar others_value) {

  if (fix_byte >= CELLS) {
    errx(1, "GenPlaintexts : fix_byte is too large\n");
  }

  for (size_t i = 0; i < NBR_PAIRS; i++) {
    // on remplie de plaintext de 0
    for (size_t j = 0; j < CELLS; j++) {
      pairs[i].plaintext[j] = others_value;
      // on initilise aussi le text chiffré avec le text clair
      pairs[i].ciphertext[j] = others_value;
    }

    // on fait varier l'octet identifié par fix_byte
    pairs[i].plaintext[fix_byte] = i;
    pairs[i].ciphertext[fix_byte] = i;
    pairs[i].ciphertext_tmp[fix_byte] = i;
  }
  return EXIT_SUCCESS;
}

/*
fonction permettant de chiffrer le clair de la structure plain_cipher
*/
uchar EncryptPlaintexts(plain_cipher *pairs, uchar **round_keys) {
  for (size_t i = 0; i < NBR_PAIRS; i++) {
    // on chiffre ciphertext qui est initialisé avec le clair
    Encryption(pairs[i].ciphertext, round_keys);
    // on copie le contenue du chiffré dans ciphertext_tmp
    CopyState(pairs[i].ciphertext, pairs[i].ciphertext_tmp);
  }
  return EXIT_SUCCESS;
}

void PrintAllPairs(plain_cipher *pairs) {
  for (size_t i = 0; i < NBR_PAIRS; i++) {
    fprintf(stdout, "%zu\n", i);
    PrintByteArray(pairs[i].plaintext, CELLS, (const uchar *)"Plaintext");
    PrintByteArray(pairs[i].ciphertext, CELLS, (const uchar *)"CipherText");
  }
}

bool CopyState(uchar *state, uchar *copy) {
  for (size_t i = 0; i < CELLS; i++) {
    copy[i] = state[i];
  }
  return EXIT_SUCCESS;
}
