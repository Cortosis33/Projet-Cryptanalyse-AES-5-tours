#include "utils.h"

uchar KEY[16] = 		 {0xd0, 0xc9, 0xe1, 0xb6,
                   		0x14, 0xee, 0x3f, 0x63,
                      0xf9, 0x25, 0x0c, 0x0c,
                      0xa8, 0x89, 0xc8, 0xa6};

uchar PLAINTEXT[16] =  {0x39, 0x02, 0xDC, 0x19,
                        0x25, 0xDC, 0x11, 0x6A,
                        0x84, 0x09, 0x85, 0x0B,
                        0x1D, 0xFB, 0x97, 0x32};



int main(int argc, char const *argv[]) {

  uchar plaintext[CELLS];
  for(uchar i = 0; i < CELLS; i++)
		plaintext[i] = PLAINTEXT[i];

  PrintByteArray(plaintext, 16, (const uchar *)"Plaintext");

  SubBytes(plaintext);

  PrintByteArray(plaintext, 16, (const uchar *)"Plaintext after SubBytes");

  ShiftRow(plaintext);

  PrintByteArray(plaintext, 16, (const uchar *)"Plaintext after ShiftRow");

  MixColumn(plaintext);

  PrintByteArray(plaintext, 16, (const uchar *)"Plaintext after MixColumn");

  uchar value = xtime(0x05);

  fprintf(stdout, "%x\n", value);

  return 0;
}
