#include "common.h"
#include "utils.h"

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

typedef struct {
  uchar p0[16];
  uchar p1[16];
} plain_couple;

typedef struct {
  plain_couple array[5];
  size_t len;
} couple_array;

// Retourne des informations sur la distances entre deux textes.
Distance InfoDist(Distance distance, uchar *text1, uchar *text2);

// Avoir seulement le nu d'un objet (Le zero différence pattern)
uchar *Nu(uchar *text);

// compare 2 vecteur et retourne la différence en V.A
uchar *CMP(uchar *text1, uchar *text2);

// Retourne le texte 2 avec le premier mot différent du texte 1 sur la colone
// active (Les textes font 16 octets)
bool SimpleSwapCol(uchar *text1, uchar *text2, uchar *Swaptmp, uchar *Swaptmp2);

// TESTS
bool EncryptionExp(uchar *plaintext, uchar **round_keys);
bool DecryptionExp(uchar *ciphertext, uchar **round_keys);

void GenPlaintexts_yoyo(plain *pset_0, plain *pset_1);
void AddList(couple_array *S, uchar *p0, uchar *p1);
void PrintSContent(couple_array S);
uchar MixColOneByte(uchar *state);
uchar ComputeVerif(uchar *state, uchar *key_guess);
bool DiagEqual(uchar *state0, uchar *state1);
