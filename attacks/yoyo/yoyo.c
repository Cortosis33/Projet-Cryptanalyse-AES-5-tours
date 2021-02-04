#include "../../include/yoyo.h"

uchar dist[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uchar ham[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Retourne la valeur absolue de la différence entre deux texte.
Distance InfoDist(Distance distance, uchar *text1, uchar *text2) {
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

// Retourne le texte 2 avec le premier mot différent du texte 1 (Les textes font
// 4 octets)
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


