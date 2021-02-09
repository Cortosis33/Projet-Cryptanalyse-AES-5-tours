#include "../../include/yoyo.h"

// to enable an attack
#define ATTACK 1
#define TEST 0

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

uchar KEY2[16] = {0x50, 0xc9, 0xe1, 0x30, 0x14, 0xe3, 0xff, 0x63,
                  0xde, 0xad, 0xbe, 0xef, 0xf9, 0x89, 0xc8, 0xa6};

uchar KEY3[16] = {0x23, 0xc9, 0xff, 0x30, 0xDD, 0xee, 0xff, 0x63,
                  0xCC, 0x00, 0xbe, 0xef, 0xf9, 0x14, 0xc8, 0x99};

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose =
  uchar **round_keys = GenRoundkeys(KEY3, 1);

  if (ATTACK) {
    fprintf(stdout, "Yoyo 5 rounds AES attack\n");

    uchar KG0[CELLS];

    // on crée les ensembles de clairs :
    plain pset_0[256];
    plain pset_1[256];

    // on genere les clairs
    GenPlaintexts_yoyo(pset_0, pset_1);

    uchar *p0;
    uchar *p1;

    // on initialise la liste S
    size_t size_S = 2 * 5;
    uchar **S = (uchar **)malloc(size_S * sizeof(uchar *));
    for (size_t k = 0; k < size_S; k++) {
      S[k] = (uchar *)malloc(16 * sizeof(uchar));
    }

    fprintf(stdout, "\n### K0 diagonal finding... ###\n");
    for (size_t i = 0; i < 256; i += 1) {

      /************** affichage ***************/
      PrintProgress(1.0 * i / 128);
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

      for (size_t key_guess_0 = 1; key_guess_0 < 256; key_guess_0++) {

        for (size_t key_guess_2 = 0; key_guess_2 < 256; key_guess_2++) {

          for (size_t key_guess_3 = 0; key_guess_3 < 256; key_guess_3++) {

            size_t j = 0;
            for (j = 0; j < size_S; j += 2) {

              // on alloue dans la clé
              key_guess[0] = key_guess_0;
              key_guess[4] = key_guess_0 ^ i;
              // key_guess[10] = 0x0c;
              key_guess[8] = key_guess_2;
              // key_guess[12] = 0xa6;
              key_guess[12] = key_guess_3;

              if (ComputeVerif(S[j], key_guess) !=
                  ComputeVerif(S[j + 1], key_guess)) {
                // si les octets son différents
                key_guess[4] = key_guess_0 ^ i ^ 255;

                if (ComputeVerif(S[j], key_guess) !=
                    ComputeVerif(S[j + 1], key_guess)) {
                  break;
                }
              }
            }
            if (j == size_S) {
              fprintf(stdout, "\npour i = %zu\n", i);
              PrintByteArray(key_guess, CELLS, (uchar *)"===> key_guess");
              IShiftRows(key_guess);
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
  }

  if (TEST) {

    size_t i = 63;

    uchar p0[16] = {0x00, 0x00, 0x00, 0x00, i,    0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uchar p1[16] = {1,    0x00, 0x00, 0x00, 1 ^ i, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00};

    EncryptionExp(p0, round_keys);
    EncryptionExp(p1, round_keys);

    uchar swap0[16];
    uchar swap1[16];

    SimpleSwapCol(p0, p1, swap0, swap1);

    DecryptionExp(swap0, round_keys);
    DecryptionExp(swap1, round_keys);

    SimpleSwapCol(swap0, swap1, p0, p1);

    uchar key_guess[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    key_guess[0] = 0xd0;
    key_guess[5] = 0xd0 ^ i;
    key_guess[10] = 0x0c;
    key_guess[15] = 0xa6;

    // commence

    uchar tmp0[16];
    uchar tmp1[16];

    uchar key_tmp0[16];
    uchar key_tmp1[16];

    // on copie les etats p0, p1
    memcpy(tmp0, p0, CELLS);
    memcpy(tmp1, p1, CELLS);
    memcpy(key_tmp0, key_guess, CELLS);
    memcpy(key_tmp1, key_guess, CELLS);

    // on applique le ShiftRows sur la clé ShiftRows(key_tmp0);
    ShiftRows(key_tmp0);
    AddRoundKey(tmp0, key_tmp0);
    SubBytes(tmp0);
    // MixColumns(tmp0);

    ShiftRows(key_tmp1);
    AddRoundKey(tmp1, key_tmp1);
    SubBytes(tmp1);
    // MixColumns(tmp1);

    AddRoundKey(tmp0, tmp1);

    MixColumns(tmp0);

    PrintByteArray(tmp0, CELLS, (uchar *)"tmp0");
  }

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
