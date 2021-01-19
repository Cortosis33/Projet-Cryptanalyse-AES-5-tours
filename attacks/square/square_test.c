#include "../../include/square.h"
#include "../../include/utils.h"
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

  if (AES_ROUNDS == 4) {
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

    // on genere les clairs du deuxieme lambda-set avec que des bits 1 à la
    // suite
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

    /**************************************************************************/
    /*                                 Attack                                 */
    /**************************************************************************/

    uchar key_guess[16];
    uchar b1 = 0;
    uchar b2 = 0;

    /***************************************/
    /*  Last Round Attack on 4 Rounds AES  */
    /***************************************/

    // on applique le IShiftRows à l'avance sur les chiffrés
    for (size_t i = 0; i < 256; i++) {
      IShiftRows(pairs_1[i].ciphertext);
      IShiftRows(pairs_2[i].ciphertext);
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
    ShiftRows(key_guess);
    PrintByteArray(key_guess, CELLS, (const uchar *)"key");

    // maintenant qu'on a la cle, on peut remonter :

    /***************************************/
    /*       Attack on the last key        */
    /***************************************/
    PrintByteArray(key_guess, CELLS, (const uchar *)"key 4");
    RewindKey(key_guess, 4, 1);
  }

  if (AES_ROUNDS == 5) {
    plain_cipher pairs_1[256];
    plain_cipher pairs_2[256];
    plain_cipher pairs_3[256];
    plain_cipher pairs_4[256];
    plain_cipher pairs_5[256];

    // on genere les clairs
    GenPlaintexts(pairs_1, 0, 0xFF);
    GenPlaintexts(pairs_2, 1, 0xFF);
    GenPlaintexts(pairs_3, 2, 0xFF);
    GenPlaintexts(pairs_4, 3, 0xFF);
    GenPlaintexts(pairs_5, 4, 0xFF);

    // on chiffre
    EncryptPlaintexts(pairs_1, round_keys);
    EncryptPlaintexts(pairs_2, round_keys);
    EncryptPlaintexts(pairs_3, round_keys);
    EncryptPlaintexts(pairs_4, round_keys);
    EncryptPlaintexts(pairs_5, round_keys);

    uchar key_guess_5[16];
    uchar key_guess_4[16];
    for (size_t i = 0; i < 16; i++) {
      key_guess_5[i] = 0;
      key_guess_4[i] = 0;
    }
    uchar b1 = 0;
    uchar b2 = 0;
    uchar b3 = 0;
    uchar b4 = 0;
    uchar b5 = 0;

    // on construit la clé
    for (size_t key_1 = 0; key_1 < 1; key_1++) {
      key_guess_5[0] = key_1;
      key_guess_5[0] = 0xe4;
      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        key_guess_5[7] = key_2;
        key_guess_5[7] = 0x9d;
        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          key_guess_5[10] = key_3;
          key_guess_5[10] = 0xd4;
          for (size_t key_4 = 0; key_4 < 256; key_4++) {
            key_guess_5[13] = key_4;
            // key_guess_5[13] = 0xc7;
            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[0] = key_0;
              b1 = 0;
              b2 = 0;
              b3 = 0;
              b4 = 0;
              b5 = 0;
              for (size_t i = 0; i < 256; i++) {
                // on remonte le tour 5
                InvATurn(pairs_1[i].ciphertext_tmp, key_guess_5, 5);
                InvATurn(pairs_2[i].ciphertext_tmp, key_guess_5, 5);
                InvATurn(pairs_3[i].ciphertext_tmp, key_guess_5, 5);
                InvATurn(pairs_4[i].ciphertext_tmp, key_guess_5, 5);
                InvATurn(pairs_5[i].ciphertext_tmp, key_guess_5, 5);

                // on remonte le tour 4
                InvATurn(pairs_1[i].ciphertext_tmp, key_guess_4, 4);
                InvATurn(pairs_2[i].ciphertext_tmp, key_guess_4, 4);
                InvATurn(pairs_3[i].ciphertext_tmp, key_guess_4, 4);
                InvATurn(pairs_4[i].ciphertext_tmp, key_guess_4, 4);
                InvATurn(pairs_5[i].ciphertext_tmp, key_guess_4, 4);

                b1 = pairs_1[i].ciphertext_tmp[0] ^ b1;
                b2 = pairs_2[i].ciphertext_tmp[0] ^ b2;
                b3 = pairs_3[i].ciphertext_tmp[0] ^ b3;
                b4 = pairs_4[i].ciphertext_tmp[0] ^ b4;
                b5 = pairs_5[i].ciphertext_tmp[0] ^ b5;

                // on reinitialise ciphertext_tmp par ciphertext
                for (size_t j = 0; j < 16; j++) {
                  pairs_1[i].ciphertext_tmp[j] = pairs_1[i].ciphertext[j];
                  pairs_2[i].ciphertext_tmp[j] = pairs_2[i].ciphertext[j];
                  pairs_3[i].ciphertext_tmp[j] = pairs_3[i].ciphertext[j];
                  pairs_4[i].ciphertext_tmp[j] = pairs_4[i].ciphertext[j];
                  pairs_5[i].ciphertext_tmp[j] = pairs_5[i].ciphertext[j];
                }
              }
              // fprintf(stdout, "b1=%x, b2=%x, b3=%x, b4=%x\n", b1, b2, b3,
              // b4);
              if (!b1 && !b2 && !b3 && !b4 && !b5) {
                PrintByteArray(key_guess_5, CELLS,
                               (const uchar *)"key_guess_5");
              }
            }
          }
        }
      }
    }
    // RewindKey(key_guess_5, 5, 1);
  }

  /*  */
  return 0;
}
