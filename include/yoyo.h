#include "utils.h"

#define NBR_PAIRS 256

typedef struct {
  uchar plaintext[CELLS];
  uchar ciphertext[CELLS];
  uchar ciphertext_tmp[CELLS];
} plain_cipher;

typedef struct {
  uchar *VecDif;
  int degres;
} Distance;

// Retourne des informations sur la distances entre deux textes.
Distance InfoDist(Distance distance, uchar *text1, uchar *text2);
