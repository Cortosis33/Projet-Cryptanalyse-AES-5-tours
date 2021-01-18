#include "square.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>

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
  plain_cipher pairs_1[256];
  plain_cipher pairs_2[256];

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

  PrintByteArray(pairs_1[255].plaintext, CELLS, (const uchar *)"Plaintext");
  PrintByteArray(pairs_1[255].ciphertext, CELLS, (const uchar *)"Encrypted");

  // PrintAllPairs(pairs_2);

  /*******************************/
  /*      Last Round Attack      */
  /*******************************/

  uchar key_guess[16];
  uchar b1 = 0;
  uchar b2 = 0;

  // on applique le IShiftRow à l'avance sur les chiffrés
  for (size_t i = 0; i < 256; i++) {
    IShiftRow(pairs_1[i].ciphertext);
    IShiftRow(pairs_2[i].ciphertext);
  }

  // pour toutes les octets de la clée
  // (on represente nos valeurs sur 1 dimension)
  for (uchar i = 0; i < 16; i++) {
    // pour toutes les valeurs possible d'un octet
    // (on utilise size_t pour que k atteigne 256)
    for (size_t k_byte = 0; k_byte < 256; k_byte++) {
      // pour tout les chiffrés
      // printf("%x\n", k_byte);
      b1 = 0;
      b2 = 0;
      for (size_t c = 0; c < 256; c++) {
        b1 = IS_box[pairs_1[c].ciphertext[i] ^ k_byte] ^ b1;
        b2 = IS_box[pairs_2[c].ciphertext[i] ^ k_byte] ^ b2;
      }
      if (b1 == 0 && b2 == 0) {
        fprintf(stdout, "i=%d, k_bye=%zx\n", i, k_byte);
        key_guess[i] = (uchar)k_byte;
      }
    }
  }
  ShiftRow(key_guess);
  PrintByteArray(key_guess, CELLS, (const uchar *)"key");

  /* Test du premier octet non concluant
uchar listfirstoctet1[255];
uchar listfirstoctet2[255];

for (int i = 0; i < 255; i++) {
  listfirstoctet1[i] = pairs_1[i].ciphertext[0];
  listfirstoctet2[i] = pairs_2[i].ciphertext[0];
}

uchar tmp1, tmp2;

for (size_t key_byte = 0; key_byte <= 0xFF; key_byte++) {
  tmp1 = 0;
  tmp2 = 0;
  for (int i = 0; i < 255; i++) {
    tmp1 ^= (IS_box[(size_t)listfirstoctet1[i] ^ key_byte]);
    tmp2 ^= (IS_box[(size_t)listfirstoctet2[i] ^ key_byte]);
  }
  if (tmp1 == 0 || tmp2 == 0) {
    printf("L'octet 1 de la clé 5 peut être %lx\n", key_byte);
  }
}
*/

  return 0;
}
