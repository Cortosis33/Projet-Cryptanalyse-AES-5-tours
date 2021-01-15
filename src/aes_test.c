#include "utils.h"

uchar SIZE_KEY = 16;

static uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                        0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

uchar PLAINTEXT[CELLS] = {0x39, 0x02, 0xDC, 0x19, 0x25, 0xDC, 0x11, 0x6A,
                          0x84, 0x09, 0x85, 0x0B, 0x1D, 0xFB, 0x97, 0x32};

// data : 3902DC1925DC116A8409850B1DFB9732

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys
  uchar **round_keys = GenRoundkeys(KEY, 0);

  /*******************************/
  /*   Encryption & Decryption   */
  /*******************************/
  PrintByteArray(PLAINTEXT, CELLS, (const uchar *)"Plaintext");

  // to encrypt
  Encryption(PLAINTEXT, round_keys);
  PrintByteArray(PLAINTEXT, CELLS, (const uchar *)"Encrypted");

  // to decrypt
  Decryption(PLAINTEXT, round_keys);
  PrintByteArray(PLAINTEXT, CELLS, (const uchar *)"Decrypted");

  /*******************************/
  /*          Some tests         */
  /*******************************/

  return 0;
}
