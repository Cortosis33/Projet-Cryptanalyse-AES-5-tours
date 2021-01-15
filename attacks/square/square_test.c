#include "square.h"
#include "utils.h"

uchar SIZE_KEY = 16;

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  // on crée un tableau de couple
  plain_cipher pairs[255];

  create_plaintexts(pairs, 0);

  print_all_plaintexts(pairs);

  return 0;
}
