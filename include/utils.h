/*
 * Utils Header
 *
 * Creation | AB | 07-11-2014
 *
 */

#ifndef UTILS_H
#define UTILS_H

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Define some useful values
 *
 * */

#define uchar unsigned char

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define TRUE 1
#define FALSE 0
#define MAX_STRING_LEN 256

#define DEBUG_LVL 1
#define ROWS 4
#define COLS 4
#define CELLS 16

#define AES_ROUNDS 10
#define AES_KEYS 11
#define AES_KEYSTR_LEN 48

#define MESSAGE_ARRAY_LEN 20
#define BYTE_VALUES 256

// PrintProgress
#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
//#define PBSTR "████████████████████████████████████████████████████████████"
//#define PBSTR "############################################################"
#define PBWIDTH 60

/* Sboxes and rcon and other tabs*/
static const uchar hamming4[16] = {0, 1, 1, 2, 1, 2, 2, 3,
                                   1, 2, 2, 3, 2, 3, 3, 4};

/* The key schedule produces the needed round keys from the initial key */
static const uchar rcon[15] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                               0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};

static const uchar S_box[256] = {
    99,  124, 119, 123, 242, 107, 111, 197, 48,  1,   103, 43,  254, 215, 171,
    118, 202, 130, 201, 125, 250, 89,  71,  240, 173, 212, 162, 175, 156, 164,
    114, 192, 183, 253, 147, 38,  54,  63,  247, 204, 52,  165, 229, 241, 113,
    216, 49,  21,  4,   199, 35,  195, 24,  150, 5,   154, 7,   18,  128, 226,
    235, 39,  178, 117, 9,   131, 44,  26,  27,  110, 90,  160, 82,  59,  214,
    179, 41,  227, 47,  132, 83,  209, 0,   237, 32,  252, 177, 91,  106, 203,
    190, 57,  74,  76,  88,  207, 208, 239, 170, 251, 67,  77,  51,  133, 69,
    249, 2,   127, 80,  60,  159, 168, 81,  163, 64,  143, 146, 157, 56,  245,
    188, 182, 218, 33,  16,  255, 243, 210, 205, 12,  19,  236, 95,  151, 68,
    23,  196, 167, 126, 61,  100, 93,  25,  115, 96,  129, 79,  220, 34,  42,
    144, 136, 70,  238, 184, 20,  222, 94,  11,  219, 224, 50,  58,  10,  73,
    6,   36,  92,  194, 211, 172, 98,  145, 149, 228, 121, 231, 200, 55,  109,
    141, 213, 78,  169, 108, 86,  244, 234, 101, 122, 174, 8,   186, 120, 37,
    46,  28,  166, 180, 198, 232, 221, 116, 31,  75,  189, 139, 138, 112, 62,
    181, 102, 72,  3,   246, 14,  97,  53,  87,  185, 134, 193, 29,  158, 225,
    248, 152, 17,  105, 217, 142, 148, 155, 30,  135, 233, 206, 85,  40,  223,
    140, 161, 137, 13,  191, 230, 66,  104, 65,  153, 45,  15,  176, 84,  187,
    22};

static const uchar IS_box[256] = {
    82,  9,   106, 213, 48,  54,  165, 56,  191, 64,  163, 158, 129, 243, 215,
    251, 124, 227, 57,  130, 155, 47,  255, 135, 52,  142, 67,  68,  196, 222,
    233, 203, 84,  123, 148, 50,  166, 194, 35,  61,  238, 76,  149, 11,  66,
    250, 195, 78,  8,   46,  161, 102, 40,  217, 36,  178, 118, 91,  162, 73,
    109, 139, 209, 37,  114, 248, 246, 100, 134, 104, 152, 22,  212, 164, 92,
    204, 93,  101, 182, 146, 108, 112, 72,  80,  253, 237, 185, 218, 94,  21,
    70,  87,  167, 141, 157, 132, 144, 216, 171, 0,   140, 188, 211, 10,  247,
    228, 88,  5,   184, 179, 69,  6,   208, 44,  30,  143, 202, 63,  15,  2,
    193, 175, 189, 3,   1,   19,  138, 107, 58,  145, 17,  65,  79,  103, 220,
    234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34,  231, 173,
    53,  133, 226, 249, 55,  232, 28,  117, 223, 110, 71,  241, 26,  113, 29,
    41,  197, 137, 111, 183, 98,  14,  170, 24,  190, 27,  252, 86,  62,  75,
    198, 210, 121, 32,  154, 219, 192, 254, 120, 205, 90,  244, 31,  221, 168,
    51,  136, 7,   199, 49,  177, 18,  16,  89,  39,  128, 236, 95,  96,  81,
    127, 169, 25,  181, 74,  13,  45,  229, 122, 159, 147, 201, 156, 239, 160,
    224, 59,  77,  174, 42,  245, 176, 200, 235, 187, 60,  131, 83,  153, 97,
    23,  43,  4,   126, 186, 119, 214, 38,  225, 105, 20,  99,  85,  33,  12,
    125};

static const unsigned char GF256_INVERSE[256] = {
    0x00, 0x01, 0x8D, 0xF6, 0xCB, 0x52, 0x7B, 0xD1, 0xE8, 0x4F, 0x29, 0xC0,
    0xB0, 0xE1, 0xE5, 0xC7, 0x74, 0xB4, 0xAA, 0x4B, 0x99, 0x2B, 0x60, 0x5F,
    0x58, 0x3F, 0xFD, 0xCC, 0xFF, 0x40, 0xEE, 0xB2, 0x3A, 0x6E, 0x5A, 0xF1,
    0x55, 0x4D, 0xA8, 0xC9, 0xC1, 0x0A, 0x98, 0x15, 0x30, 0x44, 0xA2, 0xC2,
    0x2C, 0x45, 0x92, 0x6C, 0xF3, 0x39, 0x66, 0x42, 0xF2, 0x35, 0x20, 0x6F,
    0x77, 0xBB, 0x59, 0x19, 0x1D, 0xFE, 0x37, 0x67, 0x2D, 0x31, 0xF5, 0x69,
    0xA7, 0x64, 0xAB, 0x13, 0x54, 0x25, 0xE9, 0x09, 0xED, 0x5C, 0x05, 0xCA,
    0x4C, 0x24, 0x87, 0xBF, 0x18, 0x3E, 0x22, 0xF0, 0x51, 0xEC, 0x61, 0x17,
    0x16, 0x5E, 0xAF, 0xD3, 0x49, 0xA6, 0x36, 0x43, 0xF4, 0x47, 0x91, 0xDF,
    0x33, 0x93, 0x21, 0x3B, 0x79, 0xB7, 0x97, 0x85, 0x10, 0xB5, 0xBA, 0x3C,
    0xB6, 0x70, 0xD0, 0x06, 0xA1, 0xFA, 0x81, 0x82, 0x83, 0x7E, 0x7F, 0x80,
    0x96, 0x73, 0xBE, 0x56, 0x9B, 0x9E, 0x95, 0xD9, 0xF7, 0x02, 0xB9, 0xA4,
    0xDE, 0x6A, 0x32, 0x6D, 0xD8, 0x8A, 0x84, 0x72, 0x2A, 0x14, 0x9F, 0x88,
    0xF9, 0xDC, 0x89, 0x9A, 0xFB, 0x7C, 0x2E, 0xC3, 0x8F, 0xB8, 0x65, 0x48,
    0x26, 0xC8, 0x12, 0x4A, 0xCE, 0xE7, 0xD2, 0x62, 0x0C, 0xE0, 0x1F, 0xEF,
    0x11, 0x75, 0x78, 0x71, 0xA5, 0x8E, 0x76, 0x3D, 0xBD, 0xBC, 0x86, 0x57,
    0x0B, 0x28, 0x2F, 0xA3, 0xDA, 0xD4, 0xE4, 0x0F, 0xA9, 0x27, 0x53, 0x04,
    0x1B, 0xFC, 0xAC, 0xE6, 0x7A, 0x07, 0xAE, 0x63, 0xC5, 0xDB, 0xE2, 0xEA,
    0x94, 0x8B, 0xC4, 0xD5, 0x9D, 0xF8, 0x90, 0x6B, 0xB1, 0x0D, 0xD6, 0xEB,
    0xC6, 0x0E, 0xCF, 0xAD, 0x08, 0x4E, 0xD7, 0xE3, 0x5D, 0x50, 0x1E, 0xB3,
    0x5B, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8C, 0xDD, 0x9C, 0x7D, 0xA0,
    0xCD, 0x1A, 0x41};

#define CHAR_TO_BYTE(character)                                                \
  (character < 0x40                                                            \
       ? (character - 0x30)                                                    \
       : (character < 0x50 ? (character - 0x40 + 9) : (character - 0x60 + 9)))
//#define CHAR_TO_BYTE(character) (character < '0x40'?(character -
//'0x30'):(character - '0x41'))

// MACROS
// Error handling macro
#define TEST_AND_RET(output, return_code)                                      \
  if (return_code != 0) {                                                      \
    return return_code;                                                        \
  };

#if DEBUG_LVL == 0
#define TEST_AND_PRINT(output, err_str, return_code)                           \
  if (return_code != 0) {                                                      \
    fprintf(output, "%s\n", err_str);                                          \
    return return_code;                                                        \
  };
#else
#define VERBOSE 0
#define TEST_AND_PRINT(output, err_str, return_code) ;
#endif /* DEBUG_LVL 1*/

#ifndef VERBOSE
#define VERBOSE 1
#endif

//#if DEBUG_LVL == 1
uchar PrintByteArray(uchar *message, uchar len, const uchar *name);
//#endif /* DEBUG_LVL 1*/

void PrintProgress(double percentage);

bool SubBytes(uchar *message);
bool ISubBytes(uchar *message);

uchar xtime(uchar byte_value);
uchar FieldMul(uchar byte_value, uchar coeff);

bool MixColumns(uchar *message);
bool IMixColumns(uchar *message);

bool ShiftRows(uchar *message);
bool IShiftRows(uchar *message);

bool AddRoundKey(uchar *message, uchar *key);

bool Encryption(uchar *plaintext, uchar **round_keys);
bool Decryption(uchar *ciphertext, uchar **round_keys);

bool UnrollKey(uchar *key, uchar round);
bool RollKey(uchar *key, uchar round);
bool RewindKey(uchar *key, uchar round, bool verbose);
bool PrepareKey(uchar **round_keys, uchar *key);
uchar **GenRoundkeys(uchar *key, bool verb);

bool InvATurn(uchar *ciphertext, uchar *current_key, int current_turn);

bool AllZeroArray(uchar *array, size_t size);
int RandInt(int max);
bool IsSameState(uchar *state1, uchar *state2);

unsigned hamdist(unsigned x, unsigned y);

#endif /* UTILS_H */
