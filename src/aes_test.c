#include "utils.h"
#include <stdlib.h>

uchar SIZE_KEY = 16;

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

//key : d0c9e1b614ee3f63f9250c0ca889c8a6

uchar PLAINTEXT[CELLS] = {0x39, 0x02, 0xDC, 0x19, 0x25, 0xDC, 0x11, 0x6A,
                          0x84, 0x09, 0x85, 0x0B, 0x1D, 0xFB, 0x97, 0x32};

//data : 3902DC1925DC116A8409850B1DFB9732

int main(int argc, char const *argv[]) {

  /*****************/
  /* Keys creation */
  /*****************/

  /* init dynamic key */
  uchar key[SIZE_KEY];
  for (uchar i = 0; i < SIZE_KEY; i++)
    key[i] = KEY[i];

  /* key printing */
  PrintByteArray(key, CELLS, (const uchar *)"Key");

  /* array keys allocation (round +1 keys) */
  uchar *round_keys[AES_ROUNDS + 1];

  //fprintf(stdout, "error\n");

  /* key's size allocation in the array */
  for (size_t i = 0; i < AES_ROUNDS + 1; i++) {
    round_keys[i] = (uchar *)malloc(CELLS * sizeof(uchar));
  }

  /* keys generation */
  PrepareKey(round_keys, key);

  for (size_t i = 0; i < AES_ROUNDS + 1; i++) {
    fprintf(stdout, "key %zu:\n", i);
    PrintByteArray(round_keys[i], CELLS, (const uchar *)"");
  }

  /*******************************/
  /*   Encryption & Decryption   */
  /*******************************/

  uchar plaintext[CELLS];
  for (uchar i = 0; i < CELLS; i++)
    plaintext[i] = PLAINTEXT[i];

  PrintByteArray(plaintext, CELLS, (const uchar *)"Plaintext");

  Encryption(plaintext, round_keys);

  PrintByteArray(plaintext, CELLS, (const uchar *)"Encrypted");

  Decryption(plaintext, round_keys);

  PrintByteArray(plaintext, CELLS, (const uchar *)"Decrypted");


  return 0;
}