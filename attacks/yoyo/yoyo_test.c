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
    for (size_t i = 0; i < 256; i++) {

      /************** affichage ***************/
      PrintProgress(1.0 * i / 255);
      /****************************************/

      p0 = pairs_1[i].plaintext;
      p1 = pairs_2[i].plaintext;

      // on initialise les pointeurs des chiffrées
      uchar c0tmp[CELLS];
      uchar c1tmp[CELLS];

      // on initialise la liste S
      couple_array S;
      S.len = 0;

      for (size_t j = 0; j < 4; j++) {
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

      // on definit la clé finale
      uchar key_guess[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

      // on parcourt S

      for (size_t key_guess_0 = 0; key_guess_0 < 256; key_guess_0++) {

        for (size_t key_guess_2 = 0; key_guess_2 < 256; key_guess_2++) {

          for (size_t key_guess_3 = 0; key_guess_3 < 1; key_guess_3++) {

            size_t j = 0;
            for (j = 0; j < 4; j++) {

              // uchar tmpkey0[16];
              // uchar tmpkey1[16];

              uchar tmp0[16];
              uchar tmp1[16];

              // on alloue dans la clé
              key_guess[0] = key_guess_0;
              key_guess[5] = key_guess_0 ^ i;
              // key_guess[10] = 0x0C;
              key_guess[10] = key_guess_2;
              key_guess[15] = 0xA6;
              // key_guess[15] = key_guess_3;

              // on copie les etats p0, p1
              memcpy(tmp0, (S.array[j]).p0, CELLS);
              memcpy(tmp1, (S.array[j]).p1, CELLS);

              ShiftRows(key_guess);
              for (size_t cels = 0; cels < CELLS; cels++) {
                // AddRoundKey & SubBytes
                tmp0[cels] = S_box[tmp0[cels] ^ key_guess[cels]];
                tmp1[cels] = S_box[tmp1[cels] ^ key_guess[cels]];
              }
              IShiftRows(key_guess);
              MixColumns(tmp0);
              MixColumns(tmp1);
              AddRoundKey(tmp0, tmp1);
              // on verifie la valeur du 3 ieme octet de la premiere colonne
              // if ((ComputeVerif(tmp0, key_guess) ^
              //      ComputeVerif(tmp1, key_guess)) != 0) {
              //   break;
              // }

              if (tmp0[8] != 0) {
                break;
              }
            }
            // si j = 4 alors on a bien 4 bons couples
            if (j == 4) {
              fprintf(stdout, "\npour i = %zu\n", i);
              PrintByteArray(key_guess, CELLS, (uchar *)"key_guess");
              // on sort
              goto outloops;
            }
          }
        }
      }
    }
  outloops:
    fprintf(stdout, "OK\n");
  }

  if (TEST) {
    /* Testing code */
    fprintf(stdout, "TestCode\n");

    // on cree 2 plaintexts
    uchar p0[16];
    CopyState(KEY, p0);
    PrintByteArray(p0, CELLS, (uchar *)"p0");

    MixColumns(p0);

    PrintByteArray(p0, CELLS, (uchar *)"p0 mix");

    IMixColumns(p0);

    uchar test = MixColOneByte(p0);
    fprintf(stdout, "%X\n", test);
  }

  return 0;
}
