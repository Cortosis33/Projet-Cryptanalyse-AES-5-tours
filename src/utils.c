// code inspired by "DFA" from "carte à puces" courses

#include "../include/utils.h"

/* if the DEBUG value is activated */
#if DEBUG_LVL > 0

/* ON case */

uchar PrintByteArray(uchar *message, uchar len, const uchar *name) {
  uchar return_code = EXIT_FAILURE;
  uchar i;
  printf("%s:\n\t", name);
  for (i = 0; i < len; i++) {
    printf("%.02X ", message[i]);
    if ((i % 4) == 3) {
      printf("\n\t");
    }
  }
  printf("\n");
  return_code = EXIT_SUCCESS;
  return return_code;
}

#else
/* OFF case */
uchar PrintByteArray(uchar *message, uchar len, const uchar *name) {
  return EXIT_SUCCESS;
}

#endif /* DEBUG_LVL*/

// code inspired from StackOverflow at :
// at
// https://stackoverflow.com/questions/14539867/how-to-display-a-progress-
// indicator-in-pure-c-c-cout-printf/36315819#36315819
void PrintProgress(double percentage) {
  int val = (int)(percentage * 100);
  int lpad = (int)(percentage * PBWIDTH);
  int rpad = PBWIDTH - lpad;
  printf("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
  fflush(stdout);
}

/******************************************************************************/
/***************************** AES MANAGMENT **********************************/
/******************************************************************************/

/*
SubBytes functions
*/
bool SubBytes(uchar *message) {
  for (uchar i = 0; i < CELLS; i++) {
    message[i] = S_box[message[i]];
  }
  return EXIT_SUCCESS;
}

bool ISubBytes(uchar *message) {
  for (uchar i = 0; i < CELLS; i++) {
    message[i] = IS_box[message[i]];
  }
  return EXIT_SUCCESS;
}

/*
multiplication by x in GF(2^8)
with 0x1b = 11011 = x^4+x^3+x+1 for replace x^8
*/
uchar xtime(uchar byte_value) {
  return ((byte_value << 1) ^ (((byte_value >> 7) & 1) * 0x1b));
}

uchar FieldMul(uchar byte_value, uchar coeff) {
  uchar i, tmp, result;
  result = 0x00;
  tmp = byte_value;
  i = coeff;
  // printf("xtime 0x%.2X : 0x%.2X\n", byte_value, xtime(byte_value));
  do {
    if ((i & 0x01) == 1) {
      result ^= tmp;
      // printf("temp: 0x%.2X\n", result);
    }
    tmp = xtime(tmp);
    // printf("temp: 0x%.2X\n", tmp);
    i = i >> 1;
  } while (i > 0);
  return result;
}

uchar Multiply(uchar x, uchar y) {
  return (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^
          ((y >> 2 & 1) * xtime(xtime(x))) ^
          ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
          ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

bool ShiftRows(uchar *message) {
  uchar tmp = 0;

  /* 2nd Row */
  tmp = message[4];
  message[4] = message[5];
  message[5] = message[6];
  message[6] = message[7];
  message[7] = tmp;

  /* 3rd Row */
  tmp = message[10];
  message[10] = message[8];
  message[8] = tmp;

  tmp = message[11];
  message[11] = message[9];
  message[9] = tmp;

  /* 4th Row */
  tmp = message[15];
  message[15] = message[14];
  message[14] = message[13];
  message[13] = message[12];
  message[12] = tmp;

  return EXIT_SUCCESS;
}

/* O(16) */
bool IShiftRows(uchar *message) {
  uchar tmp = 0;

  /* 4th Row */
  tmp = message[7];
  message[7] = message[6];
  message[6] = message[5];
  message[5] = message[4];
  message[4] = tmp;

  /* 3rd Row */
  tmp = message[10];
  message[10] = message[8];
  message[8] = tmp;

  tmp = message[11];
  message[11] = message[9];
  message[9] = tmp;

  /* 2nd Row */
  tmp = message[12];
  message[12] = message[13];
  message[13] = message[14];
  message[14] = message[15];
  message[15] = tmp;

  return EXIT_SUCCESS;
}

/*
MixColumns functions (equivalent to a matrix product in GF(2^8))
    2 3 1 1
A = 1 2 3 1   B = message
    3 1 1 1

it computes A*B
*/
bool MixColumns(uchar *message) {
  uchar column = 0;
  uchar v, u, t = 0;

  for (column = 0; column < 4; column++) {
    t = message[column] ^ message[4 + column] ^ message[8 + column] ^
        message[12 + column];
    u = message[column];
    v = u ^ message[4 + column];
    v = xtime(v);
    message[column] = message[column] ^ v ^ t;

    v = message[4 + column] ^ message[8 + column];
    v = xtime(v);
    message[4 + column] = message[4 + column] ^ v ^ t;

    v = message[8 + column] ^ message[12 + column];
    v = xtime(v);
    message[8 + column] = message[8 + column] ^ v ^ t;

    v = message[12 + column] ^ u;
    v = xtime(v);
    message[12 + column] = message[12 + column] ^ v ^ t;
  }

  return EXIT_SUCCESS;
}

bool IMixColumns(uchar *state) {
  int i;
  uchar a, b, c, d;
  for (i = 0; i < 4; ++i) {
    a = state[i];
    b = state[i + 4];
    c = state[i + 8];
    d = state[i + 12];

    state[i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^
               Multiply(d, 0x09);
    state[i + 4] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^
                   Multiply(d, 0x0d);
    state[i + 8] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^
                   Multiply(d, 0x0b);
    state[i + 12] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^
                    Multiply(d, 0x0e);
  }
  return EXIT_SUCCESS;
}

bool AddRoundKey(uchar *message, uchar *key) {
  for (uchar i = 0; i < CELLS; i++) {
    message[i] = message[i] ^ key[i];
  }
  return EXIT_SUCCESS;
}

bool Encryption(uchar *plaintext, uchar **round_keys) {
  /* let's start with an AddRoundKey */
  AddRoundKey(plaintext, round_keys[0]);

  /**** Rounds starts ****/
  for (uchar i = 1; i < AES_ROUNDS; i++) {
    SubBytes(plaintext);
    ShiftRows(plaintext);
    MixColumns(plaintext);
    AddRoundKey(plaintext, round_keys[i]);
  }

  /**** Last Round ****/
  SubBytes(plaintext);
  ShiftRows(plaintext);
  AddRoundKey(plaintext, round_keys[AES_ROUNDS]);

  return EXIT_SUCCESS;
}

bool Decryption(uchar *ciphertext, uchar **round_keys) {
  /* let's start with an AddRoundKey */
  AddRoundKey(ciphertext, round_keys[AES_ROUNDS]);
  IShiftRows(ciphertext);
  ISubBytes(ciphertext);

  for (uchar i = AES_ROUNDS - 1; i > 0; i--) {
    AddRoundKey(ciphertext, round_keys[i]);
    IMixColumns(ciphertext);
    IShiftRows(ciphertext);
    ISubBytes(ciphertext);
  }

  AddRoundKey(ciphertext, round_keys[0]);

  return EXIT_SUCCESS;
}

/******************************************************************************/
/**************************** KEYS MANAGMENT **********************************/
/******************************************************************************/

/* compute a 128-bits subkey from key */
bool UnrollKey(uchar *key, uchar round) {
  uchar tmp = 0;
  uchar row, column = 0;

  /* evaluate 1st col */
  tmp = key[3];
  key[0] = S_box[key[7]] ^ rcon[round] ^ key[0];
  key[4] = S_box[key[11]] ^ key[4];
  key[8] = S_box[key[15]] ^ key[8];
  key[12] = S_box[tmp] ^ key[12];

  for (row = 0; row < 4; row++) {
    for (column = 1; column < 4; column++) {
      key[(4 * row) + column] ^= key[(4 * row) + column - 1];
    }
  }

  return EXIT_SUCCESS;
}

/* reverse of UnrollKey */
bool RollKey(uchar *key, uchar round) {
  uchar tmp = 0;
  int row, column = 0;

  for (row = 3; row >= 0; row--) {
    for (column = 3; column >= 1; column--) {
      key[(4 * row) + column] ^= key[(4 * row) + column - 1];
    }
  }

  /* evaluate 1st col */
  tmp = key[3];
  key[0] = S_box[key[7]] ^ rcon[round] ^ key[0];
  key[4] = S_box[key[11]] ^ key[4];
  key[8] = S_box[key[15]] ^ key[8];
  key[12] = S_box[tmp] ^ key[12];

  return EXIT_SUCCESS;
}

/* function to rewind key_guess */
bool RewindKey(uchar *key_guess, uchar round, bool verbose) {
  if (round > AES_ROUNDS) {
    errx(1, "RewindKey : Error of round value");
  }
  for (int i = round - 1; i >= 0; i--) {
    RollKey(key_guess, i);
    if (verbose) {
      fprintf(stdout, "key : %d", i);
      PrintByteArray(key_guess, CELLS, (const uchar *)" ");
    }
  }
  return EXIT_SUCCESS;
}

/* create a list with subparts of 128-bits key */
bool PrepareKey(uchar **round_keys, uchar *key) {

  uchar return_code = EXIT_FAILURE;

  for (uchar j = 0; j < CELLS; j++) {
    round_keys[0][j] = key[j];
  }
  for (uchar i = 0; i < AES_ROUNDS; i++) {
    return_code = UnrollKey(key, i);
    for (uchar j = 0; j < CELLS; j++) {
      round_keys[i + 1][j] = key[j];
    }
  }
  return return_code;
}

/*****************/
/* Keys creation */
/*****************/

uchar **GenRoundkeys(uchar *key, bool verb) {
  fprintf(stdout,
          "############################################################\n"
          "####################### %d Rounds AES #######################\n"
          "############################################################\n",
          AES_ROUNDS);
  /* init dynamic key */
  uchar tmp_key[16];
  for (uchar i = 0; i < 16; i++)
    tmp_key[i] = key[i];

  /* array keys allocation (round +1 keys) */
  // uchar *round_keys[AES_ROUNDS + 1];
  uchar **round_keys = (uchar **)malloc((AES_ROUNDS + 1) * sizeof(uchar *));

  /* key's size allocation in the array */
  for (size_t i = 0; i < AES_ROUNDS + 1; i++) {
    round_keys[i] = (uchar *)malloc(CELLS * sizeof(uchar));
  }

  PrepareKey(round_keys, tmp_key);

  /* key printing */
  if (verb) {
    for (size_t i = 0; i < AES_ROUNDS + 1; i++) {
      fprintf(stdout, "Key %zu", i);
      PrintByteArray(round_keys[i], CELLS, (const uchar *)"");
    }
  }

  // return round_keys's adress
  return round_keys;
}

/******************************************************************************/
/*************************** OTHERS FUNCTIONS *********************************/
/******************************************************************************/

// to reverse an AES Round
bool InvATurn(uchar *ciphertext, uchar *current_key, int current_turn) {

  if (current_turn > AES_ROUNDS) {
    errx(1, "InvATurn : %d is too large\n", current_turn);
  }

  if (AES_ROUNDS == current_turn) {
    // last round
    AddRoundKey(ciphertext, current_key);
    IShiftRows(ciphertext);
    ISubBytes(ciphertext);
    return EXIT_SUCCESS;

  } else if (current_turn == 0) {
    // first round
    AddRoundKey(ciphertext, current_key);
    return EXIT_SUCCESS;

  } else {
    // others rounds
    AddRoundKey(ciphertext, current_key);
    IMixColumns(ciphertext);
    IShiftRows(ciphertext);
    ISubBytes(ciphertext);
    return EXIT_SUCCESS;
  }

  return EXIT_FAILURE;
}

// to ckeck if all array's values are equals to zero
bool AllZeroArray(uchar *array, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (array[i] != 0) {
      return FALSE;
    }
  }
  return TRUE;
}

// to return a random integer in [0,max-1]
int RandInt(int max) {
  static int first = 0;

  if (first == 0) {
    srand(time(NULL));
    first = 1;
  }
  return (rand()) % max;
}

// to compare two state and returns TRUE if they are equals
bool IsSameState(uchar *state1, uchar *state2) {
  for (size_t i = 0; i < CELLS; i++) {
    if (state1[i] != state2[i]) {
      return FALSE;
    }
  }
  return TRUE;
}

bool CopyState(uchar *state, uchar *copy) {
  for (size_t i = 0; i < CELLS; i++) {
    copy[i] = state[i];
  }
  return EXIT_SUCCESS;
}

/* compute hamming distance btwn x and y */
unsigned hamdist(unsigned x, unsigned y) {
  unsigned dist = 0, val = x ^ y; // XOR

  // Count the number of set bits
  while (val) {
    ++dist;
    val &= val - 1;
  }

  return dist;
}
