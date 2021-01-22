#include "../../include/square.h"
#include "../../include/utils.h"
#include <stdio.h>
#include <stdlib.h>

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60

#define VARIANT 0
// to enable an attack
#define ATTACK 1

uchar SIZE_KEY = 16;

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

// code inspired from StackOverflow at :
// at
// https://stackoverflow.com/questions/14539867/how-to-display-a-progress-
// indicator-in-pure-c-c-cout-printf/36315819#36315819
void printProgress(double percentage) {
  int val = (int)(percentage * 100);
  int lpad = (int)(percentage * PBWIDTH);
  int rpad = PBWIDTH - lpad;
  printf("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
  fflush(stdout);
}

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 0
  uchar **round_keys = GenRoundkeys(KEY, 0);

  if (AES_ROUNDS == 4 && ATTACK) {

    /**************************************************************************/
    /************************ ATTACK ON 4 ROUNDS AES **************************/
    /**************************************************************************/

    /*******************************/
    /*         Encryption          */
    /*******************************/

    // on crée les deux lambd-set avec un tableau de couple (clair, chiffré)
    plain_cipher pairs_1[NBR_PAIRS];
    plain_cipher pairs_2[NBR_PAIRS];

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

    uchar key_guess[CELLS];
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
        for (size_t c = 0; c < NBR_PAIRS; c++) {
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

  if (AES_ROUNDS == 5 && ATTACK) {

    /**************************************************************************/
    /************************ ATTACK ON 5 ROUNDS AES **************************/
    /**************************************************************************/

    fprintf(stdout, "plaintext/ciphertext generation...\n");

    plain_cipher **pairs_array = malloc(5 * sizeof(plain_cipher *));

    for (size_t i = 0; i < 5; i++) {
      pairs_array[i] = malloc(NBR_PAIRS * sizeof(plain_cipher));
    }

    plain_cipher pairs_1[NBR_PAIRS];
    plain_cipher pairs_2[NBR_PAIRS];
    plain_cipher pairs_3[NBR_PAIRS];
    plain_cipher pairs_4[NBR_PAIRS];
    plain_cipher pairs_5[NBR_PAIRS];

    // on genere les clairs
    for (size_t i = 0; i < 5; i++) {
      GenPlaintexts(pairs_array[i], i, 0xFF);
    }

    GenPlaintexts(pairs_1, 0, 0xFF);
    GenPlaintexts(pairs_2, 1, 0xFF);
    GenPlaintexts(pairs_3, 2, 0xFF);
    GenPlaintexts(pairs_4, 3, 0xFF);
    GenPlaintexts(pairs_5, 4, 0xFF);

    // on chiffre
    for (size_t i = 0; i < 5; i++) {
      EncryptPlaintexts(pairs_array[i], round_keys);
    }
    PrintByteArray((pairs_array[0])[0].ciphertext, CELLS,
                   (const uchar *)"plaintext");
    EncryptPlaintexts(pairs_1, round_keys);
    EncryptPlaintexts(pairs_2, round_keys);
    EncryptPlaintexts(pairs_3, round_keys);
    EncryptPlaintexts(pairs_4, round_keys);
    EncryptPlaintexts(pairs_5, round_keys);

    fprintf(stdout, "plaintext/ciphertext generation OK\n\n");

    fprintf(stdout, "key_guess generation...\n");
    uchar key_guess_5[16];
    uchar key_guess_4[16];
    for (size_t i = 0; i < 16; i++) {
      key_guess_5[i] = 0;
      key_guess_4[i] = 0;
    }
    fprintf(stdout, "key_guess generation OK\n\n");
    uchar b1 = 0;
    uchar b2 = 0;
    uchar b3 = 0;
    uchar b4 = 0;
    uchar b5 = 0;

    // on construit la clé

    /************** affichage ***************/
    double progress = 0;
    /****************************************/

    for (size_t key_1 = 0; key_1 < 256; key_1++) {
      key_guess_5[0] = key_1;
      // key_guess_5[0] = 0xe4;

      /************** affichage ***************/
      progress = (double)(1.0 * key_1 / 256);
      printProgress(progress);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        key_guess_5[7] = key_2;
        key_guess_5[7] = 0x9d;

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          // key_guess_5[10] = key_3;

          key_guess_5[10] = 0xd4;
          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            key_guess_5[13] = key_4;
            key_guess_5[13] = 0xc7;
            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[0] = key_0;
              b1 = 0;
              b2 = 0;
              b3 = 0;
              b4 = 0;
              b5 = 0;
              for (size_t i = 0; i < NBR_PAIRS; i++) {
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
                printf("\nFirst 4 bytes found ! \n");
                PrintByteArray(key_guess_5, CELLS,
                               (const uchar *)"key_guess_5");
                goto outloops1;
              }
            }
          }
        }
      }
    }
  outloops1:
    for (size_t key_1 = 0; key_1 < 256; key_1++) {

      key_guess_5[2] = key_1;
      // key_guess_5[2] = 0xeb;

      /************** affichage ***************/
      progress = (double)(1.0 * key_1 / 256);
      printProgress(progress);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        key_guess_5[5] = key_2;
        key_guess_5[5] = 0x3d;

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          // key_guess_5[8] = key_3;
          key_guess_5[8] = 0xbb;

          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            key_guess_5[15] = key_4;
            key_guess_5[15] = 0x59;
            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[2] = key_0;
              b1 = 0;
              b2 = 0;
              b3 = 0;
              b4 = 0;
              b5 = 0;
              for (size_t i = 0; i < NBR_PAIRS; i++) {
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

                b1 = pairs_1[i].ciphertext_tmp[2] ^ b1;
                b2 = pairs_2[i].ciphertext_tmp[2] ^ b2;
                b3 = pairs_3[i].ciphertext_tmp[2] ^ b3;
                b4 = pairs_4[i].ciphertext_tmp[2] ^ b4;
                b5 = pairs_5[i].ciphertext_tmp[2] ^ b5;

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
                printf("\nSecond 4 bytes found ! \n");
                PrintByteArray(key_guess_5, CELLS,
                               (const uchar *)"key_guess_5");
                goto outloops2;
              }
            }
          }
        }
      }
    }
  outloops2:
    for (size_t key_1 = 0; key_1 < 256; key_1++) {
      key_guess_5[1] = key_1;
      // key_guess_5[1] = 0xAD;

      /************** affichage ***************/
      progress = (double)(1.0 * key_1 / 256);
      printProgress(progress);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        key_guess_5[4] = key_2;
        key_guess_5[4] = 0x12;

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          // key_guess_5[11] = key_3;
          key_guess_5[11] = 0xd3;

          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            key_guess_5[14] = key_4;
            key_guess_5[14] = 0x52;
            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[1] = key_0;
              b1 = 0;
              b2 = 0;
              b3 = 0;
              b4 = 0;
              b5 = 0;
              for (size_t i = 0; i < NBR_PAIRS; i++) {
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

                b1 = pairs_1[i].ciphertext_tmp[1] ^ b1;
                b2 = pairs_2[i].ciphertext_tmp[1] ^ b2;
                b3 = pairs_3[i].ciphertext_tmp[1] ^ b3;
                b4 = pairs_4[i].ciphertext_tmp[1] ^ b4;
                b5 = pairs_5[i].ciphertext_tmp[1] ^ b5;

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
                printf("\nThird 4 bytes found ! \n");
                PrintByteArray(key_guess_5, CELLS,
                               (const uchar *)"key_guess_5");
                goto outloop3;
              }
            }
          }
        }
      }
    }
  outloop3:
    for (size_t key_1 = 0; key_1 < 256; key_1++) {
      key_guess_5[3] = key_1;
      // key_guess_5[3] = 0xB5;

      /************** affichage ***************/
      progress = (double)(1.0 * key_1 / 256);
      printProgress(progress);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        key_guess_5[6] = key_2;
        key_guess_5[6] = 0x7E;

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          key_guess_5[9] = key_3;
          key_guess_5[9] = 0xe9;

          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            key_guess_5[12] = key_4;
            key_guess_5[12] = 0x6E;
            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[3] = key_0;
              b1 = 0;
              b2 = 0;
              b3 = 0;
              b4 = 0;
              b5 = 0;
              for (size_t i = 0; i < NBR_PAIRS; i++) {
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

                b1 = pairs_1[i].ciphertext_tmp[3] ^ b1;
                b2 = pairs_2[i].ciphertext_tmp[3] ^ b2;
                b3 = pairs_3[i].ciphertext_tmp[3] ^ b3;
                b4 = pairs_4[i].ciphertext_tmp[3] ^ b4;
                b5 = pairs_5[i].ciphertext_tmp[3] ^ b5;

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
                printf("\nLast 4 bytes found ! \n");
                PrintByteArray(key_guess_5, CELLS,
                               (const uchar *)"key_guess_5");
                goto outloops;
              }
            }
          }
        }
      }
    }

  outloops:
    printf("Let's find the key ! \n");
    RewindKey(key_guess_5, 5, 1);
  }

  /* Testing code */
  /*
    plain_cipher pairs_1[NBR_PAIRS];

    GenPlaintexts(pairs_1, 0, 0xFF);

    EncryptPlaintexts(pairs_1, round_keys);

    PrintByteArray(pairs_1[0].plaintext, CELLS, (const uchar *)"plain");
    PrintByteArray(pairs_1[0].ciphertext, CELLS, (const uchar *)"cipher");

    uchar b = 0;
    for (size_t i = 0; i < NBR_PAIRS; i++) {
      for (size_t j = 0; j < CELLS; j++) {
        b = b ^ pairs_1[i].ciphertext[j];
      }
    }

    fprintf(stdout, "%x\n", b);*/
  uchar test[16];
  for (size_t i = 0; i < CELLS; i++) {
    test[i] = i;
  }

  PrintByteArray(test, CELLS, (const uchar *)"test");

  IShiftRows(test);

  PrintByteArray(test, CELLS, (const uchar *)"test");

  return 0;
}
