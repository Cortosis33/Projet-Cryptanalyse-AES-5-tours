#include "../../include/yoyo.h"

// Retourne la valeur absolue de la différence entre deux texte.
uchar dist[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uchar *VecDist(uchar *text1, uchar *text2) {
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
