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

    uchar test1[16];
    for (size_t i = 0; i < CELLS; i++) {
      test1[i] = i;
    }

    uchar test2[16];
    CopyState(test1, test2);

    test2[0] = 10;

    PrintByteArray(test1, CELLS, (const uchar *)"test1");
    PrintByteArray(test2, CELLS, (const uchar *)"test2");

    uchar tmp1[16];
    uchar tmp2[16];
  }

  return 0;
}
