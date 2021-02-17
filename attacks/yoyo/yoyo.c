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
void GenPlaintexts_yoyo(plain *pset_0, plain *pset_1) {
  for (size_t i = 0; i < NBR_PAIRS; i++) {
    // on remplie de plaintext de 0
    for (size_t j = 0; j < CELLS; j++) {
      pset_0[i].plaintext[j] = 0;
      pset_1[i].plaintext[j] = 0;
    }
    pset_0[i].plaintext[4] = i;

    pset_1[i].plaintext[0] = 255;
    pset_1[i].plaintext[4] = i ^ 255;
  }
}

void PrintSContent(couple_array S) {
  size_t size = S.len;
  for (size_t i = 0; i < size; i++) {
    fprintf(stdout, "Couple %zu :\n", i);
    PrintByteArray((S.array[i]).p0, CELLS, (uchar *)"P0");
    PrintByteArray((S.array[i]).p1, CELLS, (uchar *)"P1");
  }
}

// retourne la valeur du byte à la position 8 apres
// MixColumns(state)
uchar MixColOneByte(uchar *state) {
  return state[0] ^ state[4] ^ Multiply(state[8], 2) ^ Multiply(state[12], 3);
}

// retourne la valeur du byte à la position 8 apres
// AddRoundKey(state, key_guess)
// SubBytes(state)
// MixColumns(state)
uchar ComputeVerif(uchar *state, uchar *key_guess) {
  uchar a = S_box[state[0] ^ key_guess[0]];
  uchar b = S_box[state[4] ^ key_guess[4]];
  uchar c = S_box[state[8] ^ key_guess[8]];
  uchar d = S_box[state[12] ^ key_guess[12]];
  return a ^ b ^ xtime(c) ^ (xtime(d) ^ d);
}

bool DiagEqual(uchar *state0, uchar *state1) {
  if (state0[0] == state1[0] && state0[5] == state1[5] &&
      state0[10] == state1[10] && state0[15] == state1[15]) {
    return TRUE;
  }
  return FALSE;
}

// avant d'executer cette fonction, il faut initialiser
// les lambda sets
void FindKeyFromDiag(plain *lambdset0, plain *lambdset1, uchar *key_guess_5) {
  fprintf(stdout, "\n### K5 finding... ###\n");
  uchar b0 = 0;
  uchar b1 = 0;
  uchar *ciphertext;
  // on determine tous les octets de K5 :
  for (size_t index_key_5 = 0; index_key_5 < CELLS; index_key_5++) {

    // on genere le premier octet de la cle 5
    for (size_t key_0 = index_key_5; key_0 < 256; key_0++) {

      key_guess_5[index_key_5] = key_0;

      // on initilise le tableau b
      b0 = 0;
      b1 = 0;

      for (size_t j = 0; j < NBR_PAIRS; j++) {
        ciphertext = (lambdset0)[j].plaintext;

        // on somme les valeurs des tableaux et des chiffrés
        b0 = IS_box[ciphertext[index_key_5] ^ key_guess_5[index_key_5]] ^ b0;
      }

      for (size_t j = 0; j < NBR_PAIRS; j++) {
        ciphertext = (lambdset1)[j].plaintext;

        // on somme les valeurs des tableaux et des chiffrés
        b1 = IS_box[ciphertext[index_key_5] ^ key_guess_5[index_key_5]] ^ b1;
      }

      if (b0 == 0 && b1 == 0) {
        goto outloops2_type2;
      }
    }

  outloops2_type2:
    /************** affichage ***************/
    PrintProgress(1.0 * index_key_5 / 15);
    /****************************************/
  }
  PrintByteArray(key_guess_5, CELLS, (const uchar *)"\nkey_guess_5");
  printf("\nLet's find the key ! \n");

  RewindKey(key_guess_5, 5, 0);
  PrintByteArray(key_guess_5, CELLS, (const uchar *)"key_guess_0");
}
