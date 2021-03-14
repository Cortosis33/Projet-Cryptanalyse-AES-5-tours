#include "../../include/yoyo.h"

// to enable an attack
#define ATTACK 1
// to enable test part
#define TEST 0
// to enable random mode
#define RANDOM 1

uchar KEY0[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                  0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

uchar KEY1[16] = {0x54, 0x73, 0x20, 0x67, 0x68, 0x20, 0x4b, 0x20,
                  0x61, 0x6d, 0x75, 0x46, 0x74, 0x79, 0x6e, 0x75};

uchar KEY2[16] = {0x50, 0xc9, 0xe1, 0x30, 0x14, 0xe3, 0xff, 0x63,
                  0xde, 0xad, 0xbe, 0xef, 0xf9, 0x89, 0xc8, 0xa6};

uchar KEY3[16] = {0x23, 0xc9, 0xff, 0x30, 0xDD, 0xee, 0xff, 0x63,
                  0xCC, 0x00, 0xbe, 0xef, 0xf9, 0x14, 0xc8, 0x99};

uchar KEY4[16] = {0x04, 0xc9, 0xff, 0xaa, 0xDD, 0xfe, 0xff, 0xBB,
                  0xCC, 0x77, 0xbe, 0xef, 0x67, 0x14, 0xc8, 0x45};

uchar KEY5[16] = {0x1A, 0x66, 0x1C, 0xFF, 0xD0, 0x9B, 0xFE, 0xE5,
                  0xDA, 0x78, 0xA7, 0xE9, 0x38, 0x14, 0x7A, 0x23};

uchar KEY6[16] = {0x11, 0x22, 0x33, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA,
                  0xDA, 0xFE, 0xEE, 0x56, 0x87, 0x12, 0x46, 0x09};

uchar KEY7[16] = {0x11, 0xAA, 0x33, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA,
                  0xDA, 0xFE, 0xEE, 0x56, 0xFF, 0x12, 0x46, 0x09};

// key needs 3 lambda-set
uchar KEY8[16] = {0x38, 0xD1, 0x0B, 0x0D, 0x75, 0xA3, 0xA0, 0x46,
                  0xA1, 0x66, 0x7C, 0x38, 0xA2, 0x53, 0x25, 0x51};

uchar KEY9[16] = {0x5D, 0x72, 0xF4, 0xDD, 0xA4, 0xF6, 0x31, 0x50,
                  0x0B, 0xF2, 0x1C, 0xA8, 0x6F, 0xFD, 0xC9, 0x55};

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

/*******************************************/
/************** YOYO ATTACK ****************/
/*******************************************/
void YoyoAttack(uchar **round_keys, bool yoyo_type) {
  // printer
  if (VERBOSE) {
    fprintf(stdout,
            "############################################################"
            "\n################# Yoyo 5 rounds AES attack "
            "#################\n#########################################"
            "###################\n");
    fprintf(stdout, "======> Yoyo type : %d\n", yoyo_type);
  }

  // we define the guessing KEY
  uchar KG0[CELLS];

  // we define plaintext's sets (lambda-sets)
  plain pset_0[256];
  plain pset_1[256];

  // we create plaintexts
  GenPlaintexts_yoyo(pset_0, pset_1, yoyo_type);

  uchar *p0;
  uchar *p1;

  // init S array
  size_t size_S = 2 * 6;
  uchar **S = (uchar **)malloc(size_S * sizeof(uchar *));
  for (size_t k = 0; k < size_S; k++) {
    S[k] = (uchar *)malloc(16 * sizeof(uchar));
  }

  if (VERBOSE) {
    fprintf(stdout, "\n### K0 diagonal finding... ###\n");
  }

  size_t limit = 256;
  if (yoyo_type) {
    limit = 128;
  }

  for (size_t i = 0; i < limit; i += 1) {
    /************** affichage ***************/
    PrintProgress(1.0 * i / (limit - 1));
    /****************************************/

    // on pointe p0 et p1
    p0 = pset_0[i].plaintext;
    p1 = pset_1[i].plaintext;

    // on initialise les pointeurs des chiffrées
    uchar c0tmp[CELLS];
    uchar c1tmp[CELLS];

    for (size_t j = 0; j < size_S; j += 2) {
      // on chiffre
      EncryptionExp(p0, round_keys);
      EncryptionExp(p1, round_keys);
      // on swap
      SimpleSwapCol(p0, p1, c0tmp, c1tmp);
      // ondechiffre
      DecryptionExp(c0tmp, round_keys);
      DecryptionExp(c1tmp, round_keys);
      // on re-swap
      SimpleSwapCol(c0tmp, c1tmp, p0, p1);
      // on ajoute p0 et p1 dans S
      // AddList(&S, p0, p1);
      memcpy(S[j], p0, CELLS);
      memcpy(S[j + 1], p1, CELLS);
    }

    // PrintSContent(S);

    // on definit la clé finale
    uchar key_guess[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    for (size_t key_guess_0 = 0; key_guess_0 < 256; key_guess_0++) {

      for (size_t key_guess_2 = 0; key_guess_2 < 256; key_guess_2++) {

        for (size_t key_guess_3 = 0; key_guess_3 < 256; key_guess_3++) {

          size_t j = 0;
          for (j = 0; j < size_S; j += 2) {

            // on alloue dans la clé
            key_guess[0] = key_guess_0;
            key_guess[4] = key_guess_0 ^ i;
            // key_guess[8] = (round_keys[0])[10];
            key_guess[8] = key_guess_2;
            // key_guess[12] = (round_keys[0])[15];
            key_guess[12] = key_guess_3;

            if (ComputeVerif(S[j], key_guess) !=
                ComputeVerif(S[j + 1], key_guess)) {

              // si les octets son différents
              if (yoyo_type) {
                // on change la deuxieme valeur de la colonne 1
                key_guess[4] = key_guess_0 ^ i ^ 255;

                if (ComputeVerif(S[j], key_guess) !=
                    ComputeVerif(S[j + 1], key_guess)) {
                  break;
                }
              } else {
                break;
              }
            }
          }
          if (j == size_S) {
            IShiftRows(key_guess);
            fprintf(stdout, "\npour i = %zu\n", i);
            PrintByteArray(key_guess, CELLS, (uchar *)"===> key_guess");
            memcpy(KG0, key_guess, CELLS);
            // on sort
            goto outloops;
          }
        }
      }
    }
  }
outloops:
  fprintf(stdout, "OK\n");

  for (size_t k = 0; k < size_S; k++) {
    free(S[k]);
  }
  free(S);

  // on cherche K0

  uchar key_guess_5[16];
  for (size_t i = 0; i < CELLS; i++) {
    key_guess_5[i] = 0;
  }

  FindKeyFromDiag(KG0, key_guess_5, round_keys);

  if (IsSameState(key_guess_5, round_keys[0])) {
    fprintf(stdout, "\n======================SUCCESS======================\n");
  } else {
    fprintf(stdout, "\n======================FAILED======================\n");
  }
  // if (DiagEqual(KG0, round_keys[0])) {
  //   fprintf(stdout, "\n===========SUCCESS===========\n");
  // } else {
  //   fprintf(stdout, "\n===========FAILED===========\n");
  // }
}

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 1
  uchar KEY[CELLS];

  if (RANDOM) {
    for (size_t i = 0; i < CELLS; i++) {
      KEY[i] = (uchar)RandInt(256);
    }
  } else {
    // to default
    memcpy(KEY, KEY2, CELLS);
  }
  uchar **round_keys = GenRoundkeys(KEY, 1);

  if (ATTACK) {
    YoyoAttack(round_keys, 1);
  }

  if (TEST) {

    // size_t i = 62;
    //
    // uchar p0[16] = {0x00, 0x00, 0x00, 0x00, i,    0x00, 0x00, 0x00,
    //                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //
    // uchar p1[16] = {1,    0x00, 0x00, 0x00, 1 ^ i, 0x00, 0x00, 0x00,
    //                 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00};
    //
    // PrintByteArray(p0, CELLS, (uchar *)"p0");
    //
    // EncryptionExp(p0, round_keys);
    // EncryptionExp(p1, round_keys);
    //
    // uchar swap0[16];
    // uchar swap1[16];
    //
    // SimpleSwapCol(p0, p1, swap0, swap1);
    //
    // DecryptionExp(swap0, round_keys);
    // DecryptionExp(swap1, round_keys);
    //
    // SimpleSwapCol(swap0, swap1, p0, p1);

    // uchar key4[16] = {0x99, 0xbe, 0xd1, 0xc1, 0xeb, 0x0e, 0x0b, 0x42,
    //                   0xfb, 0x5c, 0x2b, 0x2a, 0x5c, 0x04, 0x50, 0xfe};

    uchar key0[16] = {0x54, 0x73, 0x20, 0x67, 0x68, 0x20, 0x4b, 0x20,
                      0x61, 0x6d, 0x75, 0x46, 0x74, 0x79, 0x6e, 0x75};

    uchar **round_keys = GenRoundkeys(key0, 1);

    uchar p0[16] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // RewindKey(key4, 4, 1);
    Encryption(p0, round_keys);

    PrintByteArray(p0, CELLS, (uchar *)"k");
    // ShiftRows(KEY);
    // AddRoundKey(p0, KEY);
    // AddRoundKey(p1, KEY);
    // SubBytes(p0);
    // SubBytes(p1);
    // MixColumns(p0);
    // MixColumns(p1);
    //
    // PrintByteArray(p0, CELLS, (uchar *)"p0");
    // PrintByteArray(p1, CELLS, (uchar *)"p1");
    //
    // ShiftRows(p0);

    // key_guess[0] = 0xd0;
    // key_guess[5] = 0xd0 ^ i;
    // key_guess[10] = 0x0c;
    // key_guess[15] = 0xa6;
    //
    // // commence
    //
    // uchar tmp0[16];
    // uchar tmp1[16];
    //
    // uchar key_tmp0[16];
    // uchar key_tmp1[16];
    //
    // // on copie les etats p0, p1
    // memcpy(tmp0, p0, CELLS);
    // memcpy(tmp1, p1, CELLS);
    // memcpy(key_tmp0, key_guess, CELLS);
    // memcpy(key_tmp1, key_guess, CELLS);
    //
    // // on applique le ShiftRows sur la clé ShiftRows(key_tmp0);
    // ShiftRows(key_tmp0);
    // AddRoundKey(tmp0, key_tmp0);
    // SubBytes(tmp0);
    // // MixColumns(tmp0);
    //
    // ShiftRows(key_tmp1);
    // AddRoundKey(tmp1, key_tmp1);
    // SubBytes(tmp1);
    // // MixColumns(tmp1);
    //
    // AddRoundKey(tmp0, tmp1);
    //
    // MixColumns(tmp0);
    //
    // PrintByteArray(tmp0, CELLS, (uchar *)"tmp0");
  }

  /*

pour la clé :
si on a le bon i :
p0:
        00 00 00 00
         i 00 00 00
        00 00 00 00
        00 00 00 00

  p1:
         1 00 00 00
       i^1 00 00 00
        00 00 00 00
        00 00 00 00

        on applique le chiffrement :

        XX 00 00 00
         i 00 00 00
        00 00 00 00
        00 00 00 00


  */

  // methode 1
  // // on alloue dans la clé
  // key_guess[0] = key_guess_0;
  // key_guess[5] = key_guess_0 ^ i;
  // // key_guess[10] = 0x0c;
  // key_guess[10] = key_guess_2;
  // // key_guess[15] = 0xa6;
  // key_guess[15] = key_guess_3;
  //
  // uchar tmp0[16];
  // uchar tmp1[16];
  //
  // // on copie les etats p0, p1
  // memcpy(tmp0, (S.array[j]).p0, CELLS);
  // memcpy(tmp1, (S.array[j]).p1, CELLS);
  //
  // // on applique le ShiftRows sur la clé
  // ShiftRows(key_guess);
  //
  // for (size_t cels = 0; cels < CELLS; cels++) {
  //   // AddRoundKey & SubBytes
  //   tmp0[cels] = S_box[tmp0[cels] ^ key_guess[cels]];
  //   tmp1[cels] = S_box[tmp1[cels] ^ key_guess[cels]];
  // }
  //
  // IShiftRows(key_guess);
  //
  // // if ((ComputeVerif(tmp0, key_guess) ^
  // //      ComputeVerif(tmp1, key_guess)) != 0) {
  // //   break;
  // // }
  //
  // if ((MixColOneByte(tmp0) ^ MixColOneByte(tmp1)) != 0) {
  //   break;
  // }

  return 0;
}
