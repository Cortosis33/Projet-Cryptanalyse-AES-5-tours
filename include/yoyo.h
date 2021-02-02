#include "utils.h"

#define NBR_PAIRS 256

typedef struct plain_cipher {
  uchar plaintext[CELLS];
  uchar ciphertext[CELLS];
  uchar ciphertext_tmp[CELLS];
} plain_cipher;

typedef struct Distance {
  // Le vecteur différence
  uchar *VecDif;
  // Vecteur Hamming bizarre
  uchar *VectHam;
  // A quel point sont ils éloignés
  int degres;
  // Nombres de cases identiques
  int nbrcom;
} Distance;

// Retourne des informations sur la distances entre deux textes.
Distance InfoDist(Distance distance, uchar *text1, uchar *text2);
