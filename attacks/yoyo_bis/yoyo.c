#include "../../include/yoyo_bis.h"

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

// Regarde si P0 et P1 vérifie la condition
bool Testducouple(uchar *p0, uchar *p1, uchar *k0) {
  // Ajout de K0
  for (int i = 0; i < 16; i++) {
    p0[i] ^= k0[i];
    p1[i] ^= k0[i];
  }

  SubBytes(p0);
  SubBytes(p1);

  if (p0[12] == p1[12]) {
    return TRUE;
  }

  return FALSE;
}

// Retoune True si le couple est dans la liste et false sinon
bool IsCoupleInS(uchar *p0, uchar *p1, S list) {
  if (list.len == 0) {
    return FALSE;
  }

  if (list.len == 1) {
    for (int i = 0; i < 16; i++) {
      if ((p0[i] != (list.P0[i]) && p0[i] != (list.P1[i])) ||
          (p1[i] != (list.P0[i]) && p1[i] != (list.P1[i]))) {
        return FALSE;
      }
    }
    return TRUE;
  }

  if (list.len == 2) {
    for (int i = 0; i < 16; i++) {
      if ((p0[i] != (list.P0[i]) && p0[i] != (list.P1[i]) &&
           p0[i] != (list.P2[i]) && p0[i] != (list.P3[i])) ||
          (p1[i] != (list.P0[i]) && p1[i] != (list.P1[i]) &&
           p1[i] != (list.P2[i]) && p1[i] != (list.P3[i]))) {
        return FALSE;
      }
    }
    return TRUE;
  }

  if (list.len == 3) {
    for (int i = 0; i < 16; i++) {
      if ((p0[i] != (list.P0[i]) && p0[i] != (list.P1[i]) &&
           p0[i] != (list.P2[i]) && p0[i] != (list.P3[i]) &&
           p0[i] != (list.P4[i]) && p0[i] != (list.P5[i])) ||
          (p1[i] != (list.P0[i]) && p1[i] != (list.P1[i]) &&
           p1[i] != (list.P2[i]) && p1[i] != (list.P3[i]) &&
           p1[i] != (list.P4[i]) && p1[i] != (list.P5[i]))) {
        return FALSE;
      }
    }
    return TRUE;
  }

  if (list.len == 4) {
    for (int i = 0; i < 16; i++) {
      if ((p0[i] != (list.P0[i]) && p0[i] != (list.P1[i]) &&
           p0[i] != (list.P2[i]) && p0[i] != (list.P3[i]) &&
           p0[i] != (list.P4[i]) && p0[i] != (list.P5[i]) &&
           p0[i] != (list.P6[i]) && p0[i] != (list.P7[i])) ||
          (p1[i] != (list.P0[i]) && p1[i] != (list.P1[i]) &&
           p1[i] != (list.P2[i]) && p1[i] != (list.P3[i]) &&
           p1[i] != (list.P4[i]) && p1[i] != (list.P5[i]) &&
           p1[i] != (list.P6[i]) && p1[i] != (list.P7[i]))) {
        return FALSE;
      }
    }
    return TRUE;
  }

  return FALSE;
}

// Print la structure S
void PrintS(S List) {
  printf("Etat de S :\n");
  PrintByteArray(List.P0, 16, (const uchar *)"P0 ");
  PrintByteArray(List.P1, 16, (const uchar *)"P1 ");
  PrintByteArray(List.P2, 16, (const uchar *)"P2 ");
  PrintByteArray(List.P3, 16, (const uchar *)"P3 ");
  PrintByteArray(List.P4, 16, (const uchar *)"P4 ");
  PrintByteArray(List.P5, 16, (const uchar *)"P5 ");
  PrintByteArray(List.P6, 16, (const uchar *)"P6 ");
  PrintByteArray(List.P7, 16, (const uchar *)"P7 ");
  PrintByteArray(List.P8, 16, (const uchar *)"P8 ");
  PrintByteArray(List.P9, 16, (const uchar *)"P9 ");
  printf("Len = %d\n\n", List.len);
}

// Initialise la structure et ou nétoie S.
S CreateS(S List) {
  for (int i = 0; i < 16; i++) {
    List.P1[i] = 0;
    List.P2[i] = 0;
    List.P3[i] = 0;
    List.P4[i] = 0;
    List.P5[i] = 0;
    List.P6[i] = 0;
    List.P7[i] = 0;
    List.P8[i] = 0;
    List.P9[i] = 0;
  }
  List.len = 0;
  return List;
}

bool ModEncryption(uchar *plaintext, uchar **round_keys) {
  IShiftRows(plaintext);
  Encryption(plaintext, round_keys);
  IShiftRows(plaintext);
  return EXIT_SUCCESS;
}

bool ModDecryption(uchar *plaintext, uchar **round_keys) {
  ShiftRows(plaintext);
  Decryption(plaintext, round_keys);
  IShiftRows(plaintext);
  return EXIT_SUCCESS;
}

bool ModGenPlaintexts(plain *pairs) {

  for (size_t i = 0; i < NBR_PAIRS; i++) {
    // on remplie de plaintext de 0
    for (size_t j = 0; j < CELLS; j++) {
      pairs[i].plaintext0[j] = 0;
      pairs[i].plaintext1[j] = 0;
    }
    // on fait varier l'octet identifié par active_byte_index
    pairs[i].plaintext0[4] = i;
    pairs[i].plaintext1[4] = i + 1;
    pairs[i].plaintext1[0] = 1;
  }
  return TRUE;
}

S AddList(S List, uchar *text1, uchar *text2) {
  int indice = List.len;
  if (indice > 4) {
    return List;
  }

  if (indice == 0) {
    for (int i = 0; i < 16; i++) {
      List.P0[i] = text1[i];
      List.P1[i] = text2[i];
    }
    List.len += 1;
    return List;
  }

  if (indice == 1) {
    for (int i = 0; i < 16; i++) {
      List.P2[i] = text1[i];
      List.P3[i] = text2[i];
    }
    List.len += 1;
    return List;
  }

  if (indice == 2) {
    for (int i = 0; i < 16; i++) {
      List.P4[i] = text1[i];
      List.P5[i] = text2[i];
    }
    List.len += 1;
    return List;
  }

  if (indice == 3) {
    for (int i = 0; i < 16; i++) {
      List.P6[i] = text1[i];
      List.P7[i] = text2[i];
    }
    List.len += 1;
    return List;
  }

  if (indice == 4) {
    for (int i = 0; i < 16; i++) {
      List.P8[i] = text1[i];
      List.P9[i] = text2[i];
    }
    List.len += 1;
    return List;
  }

  return List;
}

// Remplace la liste 2 par le 1
bool Copy1to0(uchar *text1, uchar *text2) {
  for (int i = 0; i < 16; i++) {
    text2[i] = text1[i];
  }
  return TRUE;
}

// On crée les clés restantes
bool CreateRemkeys(listcle *allkey) { return 0; }