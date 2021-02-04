#include "../../include/utils.h"
#include "../../include/yoyo.h"

// to enable an attack
#define ATTACK 0
#define TEST 1

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

uchar KEY2[16] = {0x50, 0xc9, 0xe1, 0x30, 0x14, 0xee, 0xff, 0x63,
                  0xde, 0xad, 0xbe, 0xef, 0xf9, 0x89, 0xc8, 0xa6};

static bool testdist = TRUE;
static bool testsimpleswap = TRUE;

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 1
  uchar **round_keys = GenRoundkeys(KEY, 1);

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
    uchar text1[4] = {0xDE, 0xAD, 0x12, 0xBF};
    uchar text2[4] = {0xDE, 0x56, 0xBE, 0xEF};
    uchar *text3 = SimpleSwap(text1, text2);
    printf("Test simpleSwap avec : \n");
    PrintByteArray(text1, 4, (const uchar *)"text1 ");
    PrintByteArray(text2, 4, (const uchar *)"text2 ");
    printf("SimpleSwap devrais être 0xDE 0xAD 0xBE 0xEF : \n");
    PrintByteArray(text3, 4, (const uchar *)"Résultat ");
    uchar text4[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uchar text5[4] = {0xDE, 0xAD, 0xBE, 0xBA};
    uchar *text6 = SimpleSwap(text4, text5);
    printf("Test simpleSwap avec : \n");
    PrintByteArray(text4, 4, (const uchar *)"text4 ");
    PrintByteArray(text5, 4, (const uchar *)"text5 ");
    printf("SimpleSwap devrais être 0xDE 0xAD 0xBE 0xEF : \n");
    PrintByteArray(text6, 4, (const uchar *)"Résultat ");
    uchar t[16] = {0xDE, 0xDE, 0xDE, 0xDE, 0xAD, 0xAD, 0xAD, 0xAD,
                   0xBE, 0xBE, 0xBE, 0xBE, 0xEF, 0xEF, 0xEF, 0xEF};

    uchar t2[16] = {0xDE, 0xDE, 0xAA, 0xDE, 0xAA, 0xAD, 0xAD, 0xAD,
                    0xBE, 0xAA, 0xBE, 0xBE, 0xEF, 0xEF, 0xEF, 0xAA};
    PrintByteArray(t, 16, (const uchar *)"t");
    PrintByteArray(t2, 16, (const uchar *)"t2 ");
    uchar *res = SimpleSwapCol(t, t2, 0);
    PrintByteArray(res, 16, (const uchar *)"Résultat pour colone 0");
    uchar *res1 = SimpleSwapCol(t, t2, 1);
    PrintByteArray(res1, 16, (const uchar *)"Résultat pour colone 1");
    uchar *res2 = SimpleSwapCol(t, t2, 2);
    PrintByteArray(res2, 16, (const uchar *)"Résultat pour colone 2");
    uchar *res3 = SimpleSwapCol(t, t2, 3);
    PrintByteArray(res3, 16, (const uchar *)"Résultat pour colone 3");
  }

  if (ATTACK) {
    fprintf(stdout, "ATTACK\n");
  }

  if (TEST) {
    /* Testing code */
    fprintf(stdout, "TestCode\n");
  }

  for (size_t i = 0; i < 100; i++) {
    PrintProgress(1.0 * i / 99);
  }

  return 0;
}
