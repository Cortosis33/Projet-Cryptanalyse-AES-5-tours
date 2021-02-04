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

// Retourne le texte 2 avec le premier mot différent du texte 1 (Les textes
// font 4 octets)
uchar tmp[4] = {0x00, 0x00, 0x00, 0x00};

uchar *SimpleSwap(uchar *text1, uchar *text2) {
  int jtmp = 0;

  for (int i = 0; i < 4; i++) {
    jtmp = i;
    if (text2[i] == text1[i]) {
      tmp[i] = text2[i];
    } else {
      tmp[i] = text1[i];
      jtmp++;
      break;
    }
  }
  if (jtmp >= 3) {
    return tmp;
  } else {
    for (int j = jtmp; j < 4; j++) {
      tmp[j] = text2[j];
    }
  }
  return tmp;
}

// Retourne le texte 2 avec le premier mot différent du texte 1 sur la colone
// active (Les textes font 16 octets)

uchar *SimpleSwapCol(uchar *text1, uchar *text2, int colone) {
  for (int i = 0; i < 16; i++) {
    dist[i] = text2[i];
  }
  for (int j = 0; j < 4; j++) {
    if (text2[4 * j + colone] != text1[4 * j + colone]) {
      dist[4 * j + colone] = text1[4 * j + colone];
      break;
    }
  }
  return dist;
}
