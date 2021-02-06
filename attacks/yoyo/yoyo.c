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
bool SimpleSwapCol(uchar *state1, uchar *state2, uchar *swaptmp1,
                   uchar *swaptmp2) {
  for (int i = 0; i < 16; i++) {
    swaptmp1[i] = state1[i];
    swaptmp2[i] = state2[i];
  }

  for (int column = 0; column < 4; column++) {
    for (int j = 0; j < 4; j++) {
      if (state2[4 * j + column] != state1[4 * j + column]) {
        for (int k = 0; k < 4; k++) {
          swaptmp1[4 * k + column] = state2[4 * k + column];
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

// dechiffrement experimental
bool DecryptionExp(uchar *ciphertext, uchar **round_keys) {
  ShiftRows(ciphertext);
  Decryption(ciphertext, round_keys);
  ShiftRows(ciphertext);
  return EXIT_SUCCESS;
}

// fonction permettant de creer les deux tableaux des plaintexts
uchar GenPlaintexts_yoyo(plain_cipher *pairs1, plain_cipher *pairs2) {

  for (size_t i = 0; i < NBR_PAIRS; i++) {
    // on remplie de plaintext de 0
    for (size_t j = 0; j < CELLS; j++) {
      pairs1[i].plaintext[j] = 0;
      // on initilise aussi le text chiffré avec le text clair
      pairs1[i].ciphertext[j] = 0;

      pairs2[i].plaintext[j] = 0;
      pairs2[i].ciphertext[j] = 0;
    }

    // on fait varier l'octet identifié par active_byte_index
    pairs1[i].plaintext[4] = i;
    pairs1[i].ciphertext[4] = i;

    pairs1[i].plaintext[0] = 1;
    pairs1[i].ciphertext[0] = 1;
    pairs1[i].plaintext[4] = i ^ 1;
    pairs1[i].ciphertext[4] = i ^ 1;
  }
  return EXIT_SUCCESS;
}

// fonction permettant d'ajouter un couple au tableau S
// on donne l'adresse de S pour le modifier dynamiquement
void AddList(couple_array *S, uchar *p0, uchar *p1) {
  size_t index = S->len;
  // on cree le couple
  plain_couple pc;
  // on stoque les valeurs
  CopyState(p0, pc.p0);
  CopyState(p1, pc.p1);
  // pc.p0 = p0;
  // pc.p1 = p1;
  // on ajoute le couple
  S->array[index] = pc;
  // on incremente la taille
  S->len = index + 1;
}

void PrintSContent(couple_array S) {
  size_t size = S.len;
  for (size_t i = 0; i < size; i++) {
    fprintf(stdout, "Couple %zu :\n", i);
    PrintByteArray((S.array[i]).p0, CELLS, (uchar *)"P0");
    PrintByteArray((S.array[i]).p1, CELLS, (uchar *)"P1");
  }
}
