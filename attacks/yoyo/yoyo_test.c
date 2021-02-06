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

    // on cree 2 plaintexts
    uchar p0[16] = {0x01, 0xc9, 0xe2, 0xb6, 0x14, 0xe3, 0x3f, 0x61,
                    0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};
    uchar p1[16] = {0xa1, 0xc9, 0xe2, 0x56, 0x14, 0xe3, 0x1f, 0xa0,
                    0x19, 0x35, 0x03, 0x1c, 0x08, 0x02, 0x18, 0xac};

    // on crée les deux lambd-set avec un tableau de couple (clair, chiffré)
    plain_cipher pairs_1[NBR_PAIRS];
    plain_cipher pairs_2[NBR_PAIRS];

    // on genere les clairs du quatrième lambda-set avec que des bits 0 à la
    // suite
    // GenPlaintexts(pairs_1, 4, 0);

    PrintByteArray(pairs_1[0].plaintext, CELLS, (uchar *)"1");
  }

  return 0;
}
