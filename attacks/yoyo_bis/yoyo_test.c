#include "../../include/utils.h"
#include "../../include/yoyo_bis.h"

// to enable an attack
#define ATTACK 1
#define TEST 0

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

uchar KEY2[16] = {0x50, 0xc9, 0xe1, 0x30, 0x14, 0xee, 0xff, 0x63,
                  0xde, 0xad, 0xbe, 0xef, 0xf9, 0x89, 0xc8, 0xa6};

uchar Swaptmp[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uchar Swaptmp2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static bool testdist = 0;
static bool testsimpleswap = 0;
static bool testIsCoupleInS = 0;

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 1

  uchar **round_keys = GenRoundkeys(KEY2, 1);

  if (testdist) {
    printf("Test différence KEY,KEY \n");
    Distance dista;
    dista = InfoDist(dista, KEY, KEY);
    PrintByteArray(dista.VecDif, 16,
                   (const uchar *)"Dif entre Key et key (expect 0)");
    PrintByteArray(dista.VectHam, 16,
                   (const uchar *)"HAM vect Dif entre Key et key (expect 1)");
    printf("degrès de distance : %i\n", dista.degres);
    printf("Nombre de cases en commun : %i\n\n", dista.nbrcom);

    printf("Test différence KEY,KEY2 \n");
    PrintByteArray(KEY, 16, (const uchar *)"Key :");
    PrintByteArray(KEY2, 16, (const uchar *)"KEY2 :");

    dista = InfoDist(dista, KEY, KEY2);
    PrintByteArray(dista.VecDif, 16, (const uchar *)"Dif entre KEY et KEY2");
    PrintByteArray(dista.VectHam, 16,
                   (const uchar *)"HAM vect Dif entre Key et key2");
    printf("degrès de distance %i\n", dista.degres);
    printf("Nombre de cases en commun : %i\n\n", dista.nbrcom);
  }

  if (testsimpleswap) {
    uchar t[16] = {0xDE, 0xDE, 0xAA, 0xAA, 0xAD, 0xAD, 0xAA, 0xAA,
                   0xBE, 0xBE, 0xBB, 0xBB, 0xEF, 0xEF, 0xCC, 0xCC};

    uchar t2[16] = {0xDE, 0xDE, 0xDE, 0xDE, 0xAD, 0xAD, 0xAD, 0xAD,
                    0xBE, 0xDE, 0xBE, 0xBE, 0xEF, 0xEF, 0xEF, 0xEF};

    PrintByteArray(t, 16, (const uchar *)"t");
    PrintByteArray(t2, 16, (const uchar *)"t2 ");
    printf("Test de SimpleSwapCol\n");
    SimpleSwapCol(t, t2, Swaptmp, Swaptmp2);
    PrintByteArray(Swaptmp, 16, (const uchar *)"Swaptmp ");
    PrintByteArray(Swaptmp2, 16, (const uchar *)"Swaptmp2 ");
    printf("Autre test :\n");
    PrintByteArray(KEY, 16, (const uchar *)"KEY");
    PrintByteArray(KEY2, 16, (const uchar *)"KEY2 ");
    Copy1to0(KEY, KEY2);
    printf("Text Copy KEY->KEY2\n");
    PrintByteArray(KEY2, 16, (const uchar *)"KEY2");
  }

  if (testIsCoupleInS) {
    uchar t[16] = {0xDE, 0xDE, 0xAA, 0xAA, 0xAD, 0xAD, 0xAA, 0xAA,
                   0xBE, 0xBE, 0xBB, 0xBB, 0xEF, 0xEF, 0xCC, 0xCC};

    uchar t2[16] = {0xDE, 0xDE, 0xDE, 0xDE, 0xAD, 0xAD, 0xAD, 0xAD,
                    0xBE, 0xDE, 0xBE, 0xBE, 0xEF, 0xEF, 0xEF, 0xEF};

    S List;
    List = CreateS(List);
    // PrintS(List);
    List.len = 2;
    for (int i = 0; i < 16; i++) {
      List.P0[i] = t[i] ^ t2[i] ^ 42;
      List.P1[i] = t[i];
      List.P2[i] = t2[i];
      List.P3[i] = t[i] ^ t2[i];
    }
    PrintS(List);
    printf("Expect TRUE ou 1 : %d\n", IsCoupleInS(t, t2, List));
    printf("Expect FALSE ou 0 : %d\n", IsCoupleInS(KEY2, KEY, List));
    List = AddList(List, KEY2, KEY);
    PrintS(List);
  }

  if (ATTACK) {
    fprintf(stdout, "ATTACK\n");

    // on genere les clairs du premier "lambda-set" avec que des bits 0 à la
    // suite
    plain pairs[256];

    ModGenPlaintexts(pairs);

    S List;
    List = CreateS(List);

    for (int i = 0; i < 256; i += 2) {
      PrintProgress(1.0 * i / 256);
      List = CreateS(List);
      List = AddList(List, pairs[i].plaintext0, pairs[i].plaintext1);

      for (size_t j = 0; j < 4; j++) {
        // on chiffre
        ModEncryption(pairs[i].plaintext0, round_keys);
        ModEncryption(pairs[i].plaintext1, round_keys);
        // on swap
        SimpleSwapCol(pairs[i].plaintext0, pairs[i].plaintext1, Swaptmp,
                      Swaptmp2);

        // Copy1to0(Swaptmp, pairs[i].plaintext0);
        // Copy1to0(Swaptmp2, pairs[i].plaintext1);

        // on dechiffre
        ModDecryption(Swaptmp, round_keys);
        ModDecryption(Swaptmp2, round_keys);
        // on re-swap
        SimpleSwapCol(Swaptmp, Swaptmp2, pairs[i].plaintext0,
                      pairs[i].plaintext1);
        // on ajoute p0 et p1 dans S
        List = AddList(List, pairs[i].plaintext0, pairs[i].plaintext1);
      }
      // On crée les clés restantes
      uchar key_guess[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      // On les teste
      for (size_t key_guess_0 = 0; key_guess_0 < 256; key_guess_0++) {
        // on alloue dans la clé
        // PrintProgress(1.0 * key_guess_0 / 256);

        key_guess[0] = key_guess_0;
        key_guess[5] = key_guess_0 ^ i;
        for (size_t key_guess_2 = 0; key_guess_2 < 256; key_guess_2++) {
          // key_guess[10] = KEY2[10];
          key_guess[10] = key_guess_2;
          for (size_t key_guess_3 = 0; key_guess_3 < 256; key_guess_3++) {
            // key_guess[15] = 0xa6;
            key_guess[15] = key_guess_3;
            uchar key_tmp[16];
            Copy1to0(key_guess, key_tmp);
            ShiftRows(key_tmp);

            if (Testducouple(List.P0, List.P1, key_tmp) &&
                Testducouple(List.P2, List.P3, key_tmp) &&
                Testducouple(List.P4, List.P5, key_tmp) &&
                Testducouple(List.P6, List.P7, key_tmp) &&
                Testducouple(List.P8, List.P9, key_tmp)) {
              // We have the first column
              PrintByteArray(key_guess, 16, (const uchar *)"La clé est ");
              PrintByteArray(key_tmp, 16, (const uchar *)"Ou la clé est ");
              // return 0;
            }
          }
        }
      }
    }
  }

  if (TEST) {
    /* Testing code */
    fprintf(stdout, "TestCode\n");
    plain pairs[256];
    ModGenPlaintexts(pairs);

    PrintByteArray(pairs[0].plaintext0, 16,
                   (const uchar *)"pairs[0].plaintext0\n");
    PrintByteArray(pairs[5].plaintext0, 16,
                   (const uchar *)"pairs[5].plaintext0\n");
    PrintByteArray(pairs[255].plaintext0, 16,
                   (const uchar *)"pairs[255].plaintext0\n");
    PrintByteArray(pairs[0].plaintext1, 16,
                   (const uchar *)"pairs[0].plaintext0\n");
    PrintByteArray(pairs[5].plaintext1, 16,
                   (const uchar *)"pairs[5].plaintext0\n");
    PrintByteArray(pairs[255].plaintext1, 16,
                   (const uchar *)"pairs[255].plaintext0\n");
  }

  for (size_t i = 0; i < 100; i++) {
    PrintProgress(1.0 * i / 99);
  }

  return 0;
}
