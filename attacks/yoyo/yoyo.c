#include "../../include/yoyo.h"

uchar dist[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Retourne la valeur absolue de la différence entre deux texte.
Distance InfoDist(Distance distance, uchar *text1, uchar *text2) {
  int deg = 0;
  for (int i = 0; i < 16; i++) {
    if (text1[i] < text2[i]) {
      dist[i] = text2[i] - text1[i];
    } else if (text1[i] > text2[i]) {
      dist[i] = text1[i] - text2[i];
    } else {
      dist[i] = 0x00;
    }
    deg += dist[i];
  }
  distance.degres = deg;
  distance.VecDif = dist;
  return distance;
}
