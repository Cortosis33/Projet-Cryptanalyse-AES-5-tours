#include "utils.h"

#define NBR_PAIRS 256

typedef struct {
  uchar plaintext[CELLS];
  uchar ciphertext[CELLS];
  uchar ciphertext_tmp[CELLS];
} plain_cipher;

// Retourne la valeur absolue de la différence entre deux texte.
uchar *VecDist(uchar *text1, uchar *text2);
