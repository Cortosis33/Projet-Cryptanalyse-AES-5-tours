#include "../../include/yoyo.h"

// to enable an attack
#define ATTACK 1
#define TEST 0

uchar KEY[16] = {0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63,
                 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6};

uchar KEY2[16] = {0x50, 0xc9, 0xe1, 0x30, 0x14, 0xe3, 0xff, 0x63,
                  0xde, 0xad, 0xbe, 0xef, 0xf9, 0x89, 0xc8, 0xa6};

// key : d0c9e1b614ee3f63f9250c0ca889c8a6

int main() {

  /*******************************/
  /*        Keys creation        */
  /*******************************/

  // to generate roundkeys with verbose = 1
  uchar **round_keys = GenRoundkeys(KEY, 1);

  if (ATTACK) {
    fprintf(stdout, "ATTACK\n");

    // on crée les deux lambd-set avec un tableau de couple (clair, chiffré)
    plain_cipher pairs_1[NBR_PAIRS];
    plain_cipher pairs_2[NBR_PAIRS];

    // on genere les clairs
    GenPlaintexts_yoyo(pairs_1, pairs_2);

    uchar *p0;
    uchar *p1;
    // pour tous les clairs
    for (size_t i = 60; i < 64; i += 2) {
      p0 = pairs_1[i].plaintext;
      p1 = pairs_2[i].plaintext;

      // on initialise les pointeurs des chiffrées
      uchar c0tmp[CELLS];
      uchar c1tmp[CELLS];

      // on initialise la liste S
      couple_array S;
      S.len = 0;

      for (size_t j = 0; j < 5; j++) {
        // on chiffre
        EncryptionExp(p0, round_keys);
        EncryptionExp(p1, round_keys);
        // on swap
        SimpleSwapCol(p0, p1, c0tmp, c1tmp);
        // SimpleSwap(p0, p1, c0tmp);
        // SimpleSwap(p1, p0, c1tmp);
        // ondechiffre
        DecryptionExp(c0tmp, round_keys);
        DecryptionExp(c1tmp, round_keys);
        // on re-swap
        SimpleSwapCol(c0tmp, c1tmp, p0, p1);
        // SimpleSwapCol(c0tmp, c1tmp, p0, p1);
        // SimpleSwap(c0tmp, c1tmp, p0);
        // SimpleSwap(c1tmp, c0tmp, p1);
        // on ajoute p0 et p1 dans S
        AddList(&S, p0, p1);
      }

      uchar key_guess[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      //{0xd0, 0x00, 0x00, 0x00, 0x00, 0xee, 0x00, 0x00,
      // 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xa6};

      // uchar key_guess_tmp[16];
      // on parcourt S

      for (size_t key_guess_0 = 0; key_guess_0 < 256; key_guess_0++) {
        key_guess[0] = key_guess_0;
        key_guess[5] = key_guess_0 ^ i;

        for (size_t key_guess_2 = 0; key_guess_2 < 1; key_guess_2++) {
          key_guess[10] = 0x0C;

          for (size_t key_guess_3 = 0; key_guess_3 < 1; key_guess_3++) {
            key_guess[15] = 0xA6;

            size_t j = 0;
            for (j = 0; j < 5; j++) {

              uchar tmpkey[16];
              uchar tmp1[16];
              CopyState((S.array[j]).p0, tmp1);
              CopyState(key_guess, tmpkey);
              ShiftRows(tmpkey);
              AddRoundKey(tmp1, tmpkey);
              SubBytes(tmp1);
              MixColumns(tmp1);

              uchar tmp2[16];
              CopyState((S.array[j]).p1, tmp2);
              CopyState(key_guess, tmpkey);
              ShiftRows(tmpkey);
              AddRoundKey(tmp2, tmpkey);
              SubBytes(tmp2);
              MixColumns(tmp2);

              AddRoundKey(tmp1, tmp2);

              if (tmp1[8] != 0) {
                break;
              }
            }
            // si j = 5 alors on a bien 5 couples ok
            if (j == 5) {
              fprintf(stdout, "pour i = %zu\n", i);
              PrintByteArray(key_guess, CELLS, (uchar *)"key_guess");
              // PrintByteArray(tmp1, CELLS, (uchar *)"==");
            }
          }
        }
      }
    }
  }

  if (TEST) {
    /* Testing code */
    fprintf(stdout, "TestCode\n");

    // on cree 2 plaintexts
    uchar p0[16] = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uchar p1[16] = {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // on initialise les pointeurs des chiffrées
    uchar c0tmp[CELLS];
    uchar c1tmp[CELLS];

    // on initialise la liste S
    couple_array S;
    S.len = 0;

    for (size_t i = 0; i < 5; i++) {
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
      AddList(&S, p0, p1);
    }

    PrintSContent(S);

    // on parcourt S
    for (size_t i = 0; i < 5; i++) {
      uchar *tmp1 = (S.array[i]).p0;
      uchar tmpkey[16];
      CopyState(KEY2, tmpkey);
      IShiftRows(tmpkey);
      AddRoundKey(tmp1, tmpkey);
      SubBytes(tmp1);
      MixColumns(tmp1);

      uchar *tmp2 = (S.array[i]).p1;
      CopyState(KEY2, tmpkey);
      IShiftRows(tmpkey);
      AddRoundKey(tmp2, tmpkey);
      SubBytes(tmp2);
      MixColumns(tmp2);

      AddRoundKey(tmp1, tmp2);

      PrintByteArray(tmp1, CELLS, (uchar *)"==");
    }
  }

  return 0;
}
