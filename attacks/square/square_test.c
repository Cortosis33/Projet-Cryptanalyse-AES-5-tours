#include "../../include/square.h"
#include "../../include/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60

#define VARIANT 0
// to enable an attack
#define ATTACK 1
#define TEST 0

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

bool AllZeroArray(uchar *array, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (array[i] != 0) {
      return FALSE;
    }
  }
  return TRUE;
}

// to return a random integer in [0,max-1]
int RandInt(int max) {
  static int first = 0;

  if (first == 0) {
    srand(time(NULL));
    first = 1;
  }
  return (rand()) % max;
}

bool IsSameState(uchar *state1, uchar *state2) {
  for (size_t i = 0; i < CELLS; i++) {
    if (state1[i] != state2[i]) {
      return FALSE;
    }
  }
  return TRUE;
}

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 1
  uchar **round_keys = GenRoundkeys(KEY, 1);

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

    /* TESTS */
    /*
    Avec la clé : {0xd0, 0xc9, 0xe1, 0xb6,
                   0x14, 0xee, 0x3f, 0x63,
                   0xf9, 0x25, 0x0c, 0x0c,
                   0xa8, 0x89, 0xc8, 0xa6};

    OTF : octets à trouver par patie
    N-L : nombre de lambd-set utilisé
    S/E : Succes de l'attaque
    T : temps de l'attaque en secondes
          +-----------------------------------------+
          |  OTF        N-L       S/E       T       |
          |   2          2         S        5,67
          |   2          3         S        8,56    |
          |   2          4         S       11,39    |
          |   2          5         S       14,26    |
          |   3          5         S     3431,75    |

                         Estimations
          |   4          5         S   878336,0 ~ 10 jours
          |   5          5         S     2560 jours ~ 7 ans

    avec 3 octets par partie à trouver : 3431,75 secondes
    */

    fprintf(stdout, "plaintext/ciphertext generation...\n");
    // on definit un nombre de lambda-set
    size_t nbr_lset = 2;

    // on initilise le tableau des lambda-sets
    plain_cipher **pairs_array = malloc(nbr_lset * sizeof(plain_cipher *));
    for (size_t i = 0; i < nbr_lset; i++) {
      pairs_array[i] = malloc(NBR_PAIRS * sizeof(plain_cipher));
    }

    // on genere les clairs
    for (size_t i = 0; i < nbr_lset; i++) {
      GenPlaintexts(pairs_array[i], i, 0x00);
    }

    // on chiffre
    for (size_t i = 0; i < nbr_lset; i++) {
      EncryptPlaintexts(pairs_array[i], round_keys);
    }
    fprintf(stdout, "plaintext/ciphertext generation OK\n\n");

    fprintf(stdout, "key_guess generation...\n");
    // on initialise les clés recherchées
    uchar key_guess_5[CELLS];
    uchar key_guess_4[CELLS];
    for (size_t i = 0; i < CELLS; i++) {
      key_guess_5[i] = 0;
      key_guess_4[i] = 0;
    }
    fprintf(stdout, "key_guess generation OK\n\n");

    // on initialise le tableau de sommes
    uchar b[nbr_lset];

    // on initilise un pointeur
    uchar *ciphertext;

    // on construit la clé
    for (size_t key_1 = 0; key_1 < 256; key_1++) {
      key_guess_5[0] = key_1;
      // key_guess_5[0] = 0xe4;

      /************** affichage ***************/
      printProgress(1.0 * key_1 / 256);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        // key_guess_5[7] = key_2;
        key_guess_5[7] = (round_keys[5])[7];

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          // key_guess_5[10] = key_3;
          key_guess_5[10] = (round_keys[5])[10];

          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            // key_guess_5[13] = key_4;
            key_guess_5[13] = (round_keys[5])[13];

            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[0] = key_0;
              // key_guess_4[0] = (round_keys[4])[0];

              // on initialise le tableau de b
              for (size_t i = 0; i < nbr_lset; i++) {
                b[i] = 0;
              }

              // Pour tout les lambd-set
              for (size_t i_pairs = 0; i_pairs < nbr_lset; i_pairs++) {

                // Pour tout les chiffrés des lambd-sets
                for (size_t i = 0; i < NBR_PAIRS; i++) {

                  ciphertext = (pairs_array[i_pairs])[i].ciphertext_tmp;

                  // on remonte le tour 5
                  InvATurn(ciphertext, key_guess_5, 5);

                  // on remonte le tour 4
                  InvATurn(ciphertext, key_guess_4, 4);

                  // on somme les valeurs des tableaux et des chiffrés
                  b[i_pairs] = ciphertext[0] ^ b[i_pairs];

                  // on replace les valeurs de ciphertext dans ciphertext_tmp
                  CopyState((pairs_array[i_pairs])[i].ciphertext, ciphertext);
                }
              }
              if (AllZeroArray(b, nbr_lset)) {
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
    fprintf(stdout, "\nError\n");
  outloops1:
    for (size_t key_1 = 0; key_1 < 256; key_1++) {
      key_guess_5[2] = key_1;

      /************** affichage ***************/
      printProgress(1.0 * key_1 / 256);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        // key_guess_5[5] = key_2;
        key_guess_5[5] = (round_keys[5])[5];

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          // key_guess_5[8] = key_3;
          key_guess_5[8] = (round_keys[5])[8];

          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            // key_guess_5[15] = key_4;
            key_guess_5[15] = (round_keys[5])[15];

            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[2] = key_0;
              // key_guess_4[2] = (round_keys[4])[2];

              // on initialise le tableau de b
              for (size_t i = 0; i < nbr_lset; i++) {
                b[i] = 0;
              }

              // Pour tout les lambd-set
              for (size_t i_pairs = 0; i_pairs < nbr_lset; i_pairs++) {

                // Pour tout les chiffrés des lambd-sets
                for (size_t i = 0; i < NBR_PAIRS; i++) {

                  ciphertext = (pairs_array[i_pairs])[i].ciphertext_tmp;

                  // on remonte le tour 5
                  InvATurn(ciphertext, key_guess_5, 5);

                  // on remonte le tour 4
                  InvATurn(ciphertext, key_guess_4, 4);

                  // on somme les valeurs des tableaux et des chiffrés
                  b[i_pairs] = ciphertext[2] ^ b[i_pairs];

                  // on reinitialise ciphertext_tmp par ciphertext
                  CopyState((pairs_array[i_pairs])[i].ciphertext, ciphertext);
                }
              }
              if (AllZeroArray(b, nbr_lset)) {
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
      printProgress(1.0 * key_1 / 256);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        // key_guess_5[4] = key_2;
        key_guess_5[4] = (round_keys[5])[4];

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          // key_guess_5[11] = key_3;
          key_guess_5[11] = (round_keys[5])[11];

          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            // key_guess_5[14] = key_4;
            key_guess_5[14] = (round_keys[5])[14];

            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[1] = key_0;

              // on initialise le tableau de b
              for (size_t i = 0; i < nbr_lset; i++) {
                b[i] = 0;
              }

              // Pour tout les lambd-set
              for (size_t i_pairs = 0; i_pairs < nbr_lset; i_pairs++) {

                // Pour tout les chiffrés des lambd-sets
                for (size_t i = 0; i < NBR_PAIRS; i++) {

                  ciphertext = (pairs_array[i_pairs])[i].ciphertext_tmp;

                  // on remonte le tour 5
                  InvATurn(ciphertext, key_guess_5, 5);

                  // on remonte le tour 4
                  InvATurn(ciphertext, key_guess_4, 4);

                  // on somme les valeurs des tableaux et des chiffrés
                  b[i_pairs] = ciphertext[1] ^ b[i_pairs];

                  // on reinitialise ciphertext_tmp par ciphertext
                  CopyState((pairs_array[i_pairs])[i].ciphertext, ciphertext);
                }
              }
              if (AllZeroArray(b, nbr_lset)) {
                printf("\nThird 4 bytes found ! \n");
                PrintByteArray(key_guess_5, CELLS,
                               (const uchar *)"key_guess_5");
                goto outloops3;
              }
            }
          }
        }
      }
    }
  outloops3:
    for (size_t key_1 = 0; key_1 < 256; key_1++) {
      key_guess_5[3] = key_1;
      // key_guess_5[3] = 0xB5;

      /************** affichage ***************/
      printProgress(1.0 * key_1 / 256);
      /****************************************/

      for (size_t key_2 = 0; key_2 < 1; key_2++) {
        // key_guess_5[6] = key_2;
        key_guess_5[6] = (round_keys[5])[6];

        for (size_t key_3 = 0; key_3 < 1; key_3++) {
          // key_guess_5[9] = key_3;
          key_guess_5[9] = (round_keys[5])[9];

          for (size_t key_4 = 0; key_4 < 1; key_4++) {
            // key_guess_5[12] = key_4;
            key_guess_5[12] = (round_keys[5])[12];

            for (size_t key_0 = 0; key_0 < 256; key_0++) {
              key_guess_4[3] = key_0;

              // on initilise le tableau b
              for (size_t i = 0; i < nbr_lset; i++) {
                b[i] = 0;
              }

              // Pour tout les lambd-set
              for (size_t i_pairs = 0; i_pairs < nbr_lset; i_pairs++) {

                // Pour tout les chiffrés des lambd-sets
                for (size_t i = 0; i < NBR_PAIRS; i++) {

                  ciphertext = (pairs_array[i_pairs])[i].ciphertext_tmp;

                  // on remonte le tour 5
                  InvATurn(ciphertext, key_guess_5, 5);

                  // on remonte le tour 4
                  InvATurn(ciphertext, key_guess_4, 4);

                  // on somme les valeurs des tableaux et des chiffrés
                  b[i_pairs] = ciphertext[3] ^ b[i_pairs];

                  // on reinitialise ciphertext_tmp par ciphertext
                  CopyState((pairs_array[i_pairs])[i].ciphertext, ciphertext);
                }
              }
              // on verifie les valeurs du tableau b
              if (AllZeroArray(b, nbr_lset)) {
                printf("\nLast 4 bytes found ! \n");
                PrintByteArray(key_guess_5, CELLS,
                               (const uchar *)"key_guess_5");
                goto outloops4;
              }
            }
          }
        }
      }
    }

  outloops4:
    printf("Let's find the key ! \n");
    RewindKey(key_guess_5, 5, 0);

    if (IsSameState(key_guess_5, KEY)) {
      fprintf(stdout, "SUCCESS\n");
    }
  }

  if (TEST) {
    /* Testing code */
    int cpt1 = 0;
    int cpt2 = 0;
    int rand = 0;
    int max = 100;
    uchar key[16];
    for (int i = 0; i < max; i++) {

      // on génère une clé :
      for (size_t j = 0; j < CELLS; j++) {
        key[j] = (uchar)RandInt(256);
      }

      for (size_t j = 0; j < AES_ROUNDS; j++) {
        UnrollKey(key, j);
      }

      rand = key[15];
      if (rand < 128) {
        cpt1++;
      } else {
        cpt2++;
      }
    }
    fprintf(stdout, "cpt1: %.2f, cpt2: %.2f\n", 100 * cpt1 * 1.0 / max,
            100 * cpt2 * 1.0 / max);
  }

  return 0;
}
