#include "../../include/yoyo.h"

uchar dist[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uchar ham[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uchar Zero[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Retourne la valeur absolue de la différence entre deux texte et d'autres
// informations.
Distance InfoDist(Distance distance, uchar *text1, uchar *text2) {
  if (text2 == NULL) {
    text2 = Zero;
  }
  int deg = 0;
  int nbr = 0;
  for (int i = 0; i < 16; i++) {
    if (text1[i] < text2[i]) {
      dist[i] = text2[i] - text1[i];
      ham[i] = 0x00;
    } else if (text1[i] > text2[i]) {
      dist[i] = text1[i] - text2[i];
      ham[i] = 0x00;
    } else {
      dist[i] = 0x00;
      nbr++;
      ham[i] = 1;
    }
    deg += dist[i];
  }
  distance.degres = deg;
  distance.VecDif = dist;
  distance.nbrcom = nbr;
  distance.VectHam = ham;
  return distance;
}

// Avoir seulement le nu d'un objet (Le zero différence pattern)
uchar *Nu(uchar *text) {
  for (int i = 0; i < 16; i++) {
    if (text[i] == 0) {
      dist[i] = 1;
    } else {
      dist[i] = 0;
    }
  }
  return dist;
}

// compare 2 vecteur et retourne la différence en V.A
uchar *CMP(uchar *text1, uchar *text2) {
  for (int i = 0; i < 16; i++) {
    if (text1[i] < text2[i]) {
      dist[i] = text2[i] - text1[i];
    } else if (text1[i] > text2[i]) {
      dist[i] = text1[i] - text2[i];
    } else {
      dist[i] = 0x00;
    }
  }
  return dist;
}

// Retourne le texte 2 avec le premier mot différent du texte 1 sur la colone
// active (Les textes font 16 octets)

bool SimpleSwapCol(uchar *state1, uchar *state2, uchar *swaptmp,
                   uchar *swaptmp2) {
  for (int i = 0; i < 16; i++) {
    swaptmp[i] = state1[i];
    swaptmp2[i] = state2[i];
  }

  for (int column = 0; column < 4; column++) {
    for (int j = 0; j < 4; j++) {
      if (state2[4 * j + column] != state1[4 * j + column]) {
        for (int k = 0; k < 4; k++) {
          swaptmp[4 * k + column] = state2[4 * k + column];
          swaptmp2[4 * k + column] = state1[4 * k + column];
        }
        return TRUE;
      }
    }
  }
  return TRUE;
}

// chiffrement experimental sans le premier et le dernier ShiftRows
bool EncryptionExp(uchar *plaintext, uchar **round_keys) {
  IShiftRows(plaintext);
  Encryption(plaintext, round_keys);
  IShiftRows(plaintext);
  return EXIT_SUCCESS;
}

bool DecryptionExp(uchar *ciphertext, uchar **round_keys) {
  ShiftRows(ciphertext);
  Decryption(ciphertext, round_keys);
  IShiftRows(ciphertext);
  return EXIT_SUCCESS;
}
