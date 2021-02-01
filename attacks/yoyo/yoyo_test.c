#include "../../include/utils.h"
#include "../../include/yoyo.h"

// to enable an attack
#define ATTACK 0
#define TEST 1

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

uchar KEY2[16] = {0x50, 0xc9, 0xe1, 0x30, 0x14, 0xee, 0xff, 0x63,
                  0xf9, 0xde, 0xad, 0xbe, 0xef, 0x89, 0xc8, 0xa6};

static bool testdist = TRUE;

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 1
  uchar **round_keys = GenRoundkeys(KEY, 1);

  if (testdist) {
    printf("Test vect diff KEY,KEY \n");
    Distance dista;
    dista = InfoDist(dista, KEY, KEY);
    PrintByteArray(dista.VecDif, 16,
                   (const uchar *)"Dif entre Key et key (expect 0)");
    printf("degrès de distance %i\n", dista.degres);
    printf("Test vect diff KEY,KEY2 \n");

    dista = InfoDist(dista, KEY, KEY2);
    PrintByteArray(dista.VecDif, 16, (const uchar *)"Dif entre KEY et KEY2");
    printf("degrès de distance %i\n", dista.degres);
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
