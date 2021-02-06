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

// Avoir seulement le nu d'un objet (Le zero différence pattern)
uchar *Nu(uchar *text);

// compare 2 vecteur et retourne la différence en V.A
uchar *CMP(uchar *text1, uchar *text2);

// Retourne le texte 2 avec le premier mot différent du texte 1 sur la colone
// active (Les textes font 16 octets)
bool SimpleSwapCol(uchar *text1, uchar *text2, uchar *Swaptmp, uchar *Swaptmp2);

typedef struct S {
  // Les texts
  uchar P0[16];
  uchar P1[16];
  uchar P2[16];
  uchar P3[16];
  uchar P4[16];
  uchar P5[16];
  uchar P6[16];
  uchar P7[16];
  uchar P8[16];
  uchar P9[16];

  // La taille
  int len;

} S;

// Regarde si P0 et P1 vérifie la condition
bool Testducouple(uchar *p0, uchar *p1, uchar *k0);

// Retoune True si le couple est dans la liste et false sinon
bool IsCoupleInS(uchar *p0, uchar *p1, S list);

// Print la structure S
void PrintS(S List);

// Initialise la structure
S CreateS(S List);

// chiffrement et déchiffrement modifié avec les Shiftrows
bool ModEncryption(uchar *plaintext, uchar **round_keys);
bool ModDecryption(uchar *plaintext, uchar **round_keys);

typedef struct plain {
  uchar plaintext0[CELLS];
  uchar plaintext1[CELLS];
  uchar text_tmp[CELLS];
} plain;

// Génère les textes
bool ModGenPlaintexts(plain *pairs);

// Ajoute une paire à la liste
bool AddList(S List, uchar *text1, uchar *text2);

// Remplace la liste 2 par le 1
bool Copy1to0(uchar *text1, uchar *text2);

typedef struct listcle {
  uchar key[16];
} listcle;

// On crée les clés restantes
bool CreateRemkeys(listcle *allkey);