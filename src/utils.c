// code inspired by "DFA" from "carte à puces" courses

#include "utils.h"
#include "stdlib.h"

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

/******************************************************************************/
/***************************** AES MANAGMENT **********************************/
/******************************************************************************/

/*
SubBytes functions
*/
bool SubBytes(uchar *message) {
  for (unsigned int i = 0; i < CELLS; i++) {
    message[i] = S_box[message[i]];
  }
  return EXIT_SUCCESS;
}

bool ISubBytes(uchar *message) {
  for (unsigned int i = 0; i < CELLS; i++) {
    message[i] = IS_box[message[i]];
  }
  return EXIT_SUCCESS;
}

/*
multiplication by x in GF(2^8)
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

bool ShiftRow(uchar *message) {
  uchar tmp;

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

bool IShiftRow(uchar *message) {
  uchar tmp;

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
MixColumn functions (equivalent to a matrix product in GF(2^8))
    2 3 1 1
A = 1 2 3 1   B = message
    3 1 1 1

it computes A*B
*/
bool MixColumn(uchar *message) {
  uchar column;
  uchar v, u, t;

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

bool IMixColumn(uchar *message) {
  uchar return_code = EXIT_FAILURE;
  uchar column;
  uchar v, u;
  for (column = 0; column < 4; column++) {
    u = xtime(xtime(message[column + 0] ^ message[column + 8]));
    v = xtime(xtime(message[column + 4] ^ message[column + 12]));
    message[column + 0] = message[column + 0] ^ u;
    message[column + 4] = message[column + 4] ^ v;
    message[column + 8] = message[column + 8] ^ u;
    message[column + 12] = message[column + 12] ^ v;
  }
  return_code = MixColumn(message);
  return return_code;
}

bool AddRoundKey(uchar *message, uchar *key) {
  for (size_t i = 0; i < CELLS; i++) {
    message[i] = message[i] ^ key[i];
  }
  return EXIT_SUCCESS;
}

bool Encryption(uchar *plaintext, uchar **round_keys) {
  /* let's start with an AddRoundKey */
  AddRoundKey(plaintext, round_keys[0]);

  /**** Rounds starts ****/
  for (size_t i = 1; i < AES_ROUNDS; i++) {
    SubBytes(plaintext);
    ShiftRow(plaintext);
    MixColumn(plaintext);
    AddRoundKey(plaintext, round_keys[i]);
  }

  /**** Last Round ****/
  SubBytes(plaintext);
  ShiftRow(plaintext);
  AddRoundKey(plaintext, round_keys[AES_ROUNDS]);

  return EXIT_SUCCESS;
}

bool Decryption(uchar *ciphertext, uchar **round_keys) {
  /* let's start with an AddRoundKey */
  AddRoundKey(ciphertext, round_keys[AES_ROUNDS]);
  IShiftRow(ciphertext);
  ISubBytes(ciphertext);

  for (size_t i = AES_ROUNDS - 1; i > 0; i--) {
    AddRoundKey(ciphertext, round_keys[i]);
    IMixColumn(ciphertext);
    IShiftRow(ciphertext);
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
  uchar tmp;
  uchar row;
  uchar column;

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

/* create a list with subparts of 128-bits key */
bool PrepareKey(uchar **round_keys, uchar *key) {
  uchar i, j;
  uchar return_code = EXIT_FAILURE;

  for (j = 0; j < CELLS; j++) {
    round_keys[0][j] = key[j];
  }
  for (i = 0; i < AES_ROUNDS; i++) {
    return_code = UnrollKey(key, i);
    for (j = 0; j < CELLS; j++) {
      round_keys[i + 1][j] = key[j];
    }
  }
  return return_code;
}

/* compute hamming distance */
unsigned hamdist(unsigned x, unsigned y) {
  unsigned dist = 0, val = x ^ y; // XOR

  // Count the number of set bits
  while (val) {
    ++dist;
    val &= val - 1;
  }

  return dist;
}

uchar InvATurn(uchar *ciphertext, uchar **round_keys, int current_turn) {

  if (current_turn > AES_ROUNDS) {
    return EXIT_FAILURE;
  }

  if (AES_ROUNDS == current_turn) {
    AddRoundKey(ciphertext, round_keys[AES_ROUNDS]);
    IShiftRow(ciphertext);
    ISubBytes(ciphertext);
    return EXIT_SUCCESS;

  } else if (current_turn == 0) {
    AddRoundKey(ciphertext, round_keys[0]);
    return EXIT_SUCCESS;

  } else {
    AddRoundKey(ciphertext, round_keys[current_turn]);
    IMixColumn(ciphertext);
    IShiftRow(ciphertext);
    ISubBytes(ciphertext);
    return EXIT_SUCCESS;
  }

  return EXIT_FAILURE;
}
