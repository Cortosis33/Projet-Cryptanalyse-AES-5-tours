#include "../../include/utils.h"
#include "../../include/yoyo.h"

// to enable an attack
#define ATTACK 0
#define TEST 1

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

uchar KEY2[16] = {0x50, 0xc9, 0xe1, 0x30, 0x14, 0xee, 0xff, 0x63,
                  0xde, 0xad, 0xbe, 0xef, 0xf9, 0x89, 0xc8, 0xa6};

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 1
  uchar **round_keys = GenRoundkeys(KEY, 1);

  if (ATTACK) {
    fprintf(stdout, "ATTACK\n");
  }

  if (TEST) {
    /* Testing code */
    fprintf(stdout, "TestCode\n");

    // // on cree 2 plaintexts
    // uchar p0[16] = {0x01, 0xc9, 0xe2, 0xb6, 0x14, 0xe3, 0x3f, 0x61,
    //                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};
    // uchar p1[16] = {0xa1, 0xc9, 0xe2, 0x56, 0x14, 0xe3, 0x1f, 0xa0,
    //                 0x19, 0x35, 0x03, 0x1c, 0x08, 0x02, 0x18, 0xac};
    //
    // // on affiche les plaintexts
    // PrintByteArray(p0, CELLS, (uchar *)"p0");
    // PrintByteArray(p1, CELLS, (uchar *)"p1");
    //
    // // on chiffre les plaintexts
    // Encryption(p0, round_keys);
    // Encryption(p1, round_keys);
    //
    // // on affiche les chiffrés
    // PrintByteArray(p0, CELLS, (uchar *)"c1");
    // PrintByteArray(p1, CELLS, (uchar *)"c2");
    //
    // // on definit les pointeurs temporaires pour les swaps
    // uchar ctmp1[CELLS];
    // uchar ctmp2[CELLS];
    //
    // // on swap
    // SimpleSwapCol(p0, p1, ctmp1, ctmp2);
    //
    // // on dechiffre
    // Decryption(ctmp1, round_keys);
    // Decryption(ctmp2, round_keys);
    //
    // // on re-swap
    // SimpleSwapCol(ctmp1, ctmp2, p0, p1);
    //
    // // on affiche les chiffrés
    // PrintByteArray(p0, CELLS, (uchar *)"p0");
    // PrintByteArray(p1, CELLS, (uchar *)"p1");
    //
    // Encryption_bis(p0, round_keys);
    // Encryption_bis(p1, round_keys);
    //
    // PrintByteArray(p0, CELLS, (uchar *)"p0");
    // PrintByteArray(p1, CELLS, (uchar *)"p1");

    uchar p0[16] = {0x01, 0xc9, 0xe2, 0xb6, 0x14, 0xe3, 0x3f, 0x61,
                    0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

    uchar p0p[16] = {0x01, 0xc9, 0xe2, 0xb6, 0x14, 0xe3, 0x3f, 0x61,
                     0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

    PrintByteArray(p0, CELLS, (uchar *)"p0");

    Encryption_bis(p0, round_keys);

    PrintByteArray(p0, CELLS, (uchar *)"c0_bis");

    EncryptionExp(p0p, round_keys);

    PrintByteArray(p0p, CELLS, (uchar *)"c0_exp");
  }

  return 0;
}
