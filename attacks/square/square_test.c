#include "square.h"
#include "utils.h"

uchar SIZE_KEY = 16;

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys
  uchar **round_keys = GenRoundkeys(KEY, 1);

  /*******************************/
  /*         Encryption          */
  /*******************************/

  // on crée les deux lambd-set avec un tableau de couple (clair, chiffré)
  plain_cipher pairs_1[255];
  plain_cipher pairs_2[255];

  // on genere les clairs du premier lambda-set avec que des bits 0 à la suite
  GenPlaintexts(pairs_1, 0, 0xFF);
  /* Exemple :
        01 FF FF FF
        FF FF FF FF
        FF FF FF FF
        FF FF FF FF
  */
  // PrintAllPairs(pairs_1);

  // on genere les clairs du deuxieme lambda-set avec que des bits 1 à la suite
  GenPlaintexts(pairs_2, 1, 0xFF);
  /* Exemple :
        FF 01 FF FF
        FF FF FF FF
        FF FF FF FF
        FF FF FF FF
  */
  // PrintAllPairs(pairs_2);

  // chiffrements des clairs dans plaintext de la structure plain_cipher
  EncryptPlaintexts(pairs_1, round_keys);
  EncryptPlaintexts(pairs_2, round_keys);

  PrintByteArray(pairs_1[0].plaintext, CELLS, (const uchar *)"Plaintext");
  PrintByteArray(pairs_1[0].ciphertext, CELLS, (const uchar *)"Encrypted");

  // PrintAllPairs(pairs_2);

  /*******************************/
  /*      Last Round Attack      */
  /*******************************/

  uchar key_guess[16];
  uchar b1 = 0;
  uchar b2 = 0;
  // pour toutes les valeurs de la clée
  // (on represente nos valeurs sur 1 dimension)
  for (uchar i = 0; i < 4; i++) {
    // pour toutes les valeurs possible d'un octet
    // (on utilise size_t pour que k atteigne 256)
    for (size_t k_byte = 0; k_byte < 256; k_byte++) {
      // pour tout les chiffrés
      // printf("%x\n", k_byte);
      b1 = 0;
      b2 = 0;
      for (uchar c = 0; c < 255; c++) {
        b1 = IS_box[pairs_1[c].ciphertext[i] ^ k_byte] ^ b1;
        b2 = IS_box[pairs_2[c].ciphertext[i] ^ k_byte] ^ b2;
      }
      // fprintf(stdout, "%zx, %x, %x\n", k_byte, b1, b2);
      if (b1 == 0 && b2 == 0) {
        fprintf(stdout, "k_byte is : %zx\n", k_byte);
      }
      // key_guess[i] = (uchar)k_byte;
    }
  }

  return 0;
}
