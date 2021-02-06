#include "../include/common.h"

/*
fonction permettant de creer le tableau des plaintexts
*/
uchar GenPlaintexts(plain_cipher *pairs, uchar active_byte_index,
                    uchar others_value_content) {

  if (active_byte_index >= CELLS) {
    errx(1, "GenPlaintexts : active_byte_index is too large\n");
  }

  for (size_t i = 0; i < NBR_PAIRS; i++) {
    // on remplie de plaintext de 0
    for (size_t j = 0; j < CELLS; j++) {
      pairs[i].plaintext[j] = others_value_content;
      // on initilise aussi le text chiffré avec le text clair
      pairs[i].ciphertext[j] = others_value_content;
    }

    // on fait varier l'octet identifié par active_byte_index
    pairs[i].plaintext[active_byte_index] = i;
    pairs[i].ciphertext[active_byte_index] = i;
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
