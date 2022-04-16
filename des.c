/*
    @file des.c
    @author Nils Ruf

    A very simple DES and TDES implementation.
    This code must not be used in production as it is not optimized and is
   certainly vulnerable to side channel attacks!
*/
#include <stdio.h>

#include "des.h"
#include <assert.h>

#define BIT_AT(pos) ((block_t)1 << (pos))

#define BLOCK_SIZE 64
#define KEY_SIZE 56
#define NUM_ROUNDS 16
#define ROUND_KEY_SIZE 48
#define EXPANSION_SIZE ROUND_KEY_SIZE
#define BLOCK_SIZE_BYTES (BLOCK_SIZE / 8)
#define BLOCK_ADDR_MASK (BLOCK_SIZE / 8 - 1)
#define SBOX_SIZE 64
#define NUM_SBOXES 8
#define SBOX_IDX_LEN 6
#define SBOX_IDX_MASK (BIT_AT(SBOX_IDX_LEN) - 1)

#define HALF_BLOCK_SIZE (BLOCK_SIZE / 2)
#define HALF_BLOCK_MASK ((half_block_t)-1)
#define RIGHT_HALF(block) ((block)&HALF_BLOCK_MASK)
#define LEFT_HALF(block) (((block) >> HALF_BLOCK_SIZE) & HALF_BLOCK_MASK)
#define SWAP_LR(block) (((block) >> HALF_BLOCK_SIZE) | ((block) << HALF_BLOCK_SIZE))

#define CX(block) ((block) & (BIT_AT(KEY_SIZE / 2) - 1))
#define DX(block) (((block) >> (KEY_SIZE / 2)) & (BIT_AT(KEY_SIZE / 2) - 1))
#define STACK_CD(c, d) ((c) | ((d) << (KEY_SIZE / 2)))
#define KEY_DERIV_LEFT_ROTATE(v, shamt)                                                            \
    ((((v) << (shamt)) | ((v) >> ((KEY_SIZE / 2) - (shamt)))) & (BIT_AT(KEY_SIZE / 2) - 1))

#define CONCAT(left, right) ((block_t)(right) | ((block_t)(left) << HALF_BLOCK_SIZE))
#define PARITY_MASK(nibble) (((0x6996 >> (nibble)) << 7) & BIT_AT(7))

#define ROUND_INDEX(round, mode)                                                                   \
    ((mode) == CRYPT_MODE_ENCRYPT ? (round) : (NUM_ROUNDS - 1 - (round)))

#define INVERSE_CRYPT_MODE(crypt_mode)                                                             \
    ((crypt_mode) == CRYPT_MODE_ENCRYPT ? CRYPT_MODE_DECRYPT : CRYPT_MODE_ENCRYPT)

// Some type definitions for readability
typedef uint64_t key56_t;
typedef key56_t key112_t[2];
typedef uint64_t round_key_t;
typedef round_key_t des_round_keys_t[NUM_ROUNDS];
typedef des_round_keys_t tdes_round_keys_t[2];
typedef uint32_t permuted_key_part_t;

typedef struct {
    permuted_key_part_t c;
    permuted_key_part_t d;
    uint32_t round;
} round_key_generator_t;

typedef uint64_t block_t;
typedef uint64_t permute_block_t;
typedef uint32_t half_block_t;

typedef uint8_t init_permutation_t[BLOCK_SIZE];
typedef uint8_t init_generator_permutation_t[KEY_SIZE];
typedef uint8_t key_generator_permutation_t[EXPANSION_SIZE];
typedef const uint8_t *const permutation_t;

typedef uint8_t sbox_t[SBOX_SIZE];

typedef enum {
    CRYPT_MODE_ENCRYPT,
    CRYPT_MODE_DECRYPT,
} crypt_mode_t;

// Some type width checks
static_assert(sizeof(block_t) == 8, "Block length must be 64 bit.");
static_assert(sizeof(plain_des_key_t) == sizeof(block_t),
              "Plain key type must have same length as block type.");
static_assert(sizeof(permute_block_t) == sizeof(block_t),
              "Permutation type must have same length as block type.");
static_assert(sizeof(round_key_t) == sizeof(block_t),
              "Round key type must have same length as block type.");

// These lookup tables represent the initial permutation and its inverse
static const init_permutation_t ip = {
    57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35, 27, 19, 11, 3,  61, 53, 45, 37, 29, 21,
    13, 5,  63, 55, 47, 39, 31, 23, 15, 7,  56, 48, 40, 32, 24, 16, 8,  0,  58, 50, 42, 34,
    26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,  62, 54, 46, 38, 30, 22, 14, 6,
};

static const init_permutation_t ipinv = {
    39, 7,  47, 15, 55, 23, 63, 31, 38, 6,  46, 14, 54, 22, 62, 30, 37, 5,  45, 13, 53, 21,
    61, 29, 36, 4,  44, 12, 52, 20, 60, 28, 35, 3,  43, 11, 51, 19, 59, 27, 34, 2,  42, 10,
    50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25, 32, 0,  40, 8,  48, 16, 56, 24,
};

// These permutations are used for the rond key generation
static const init_generator_permutation_t permuted_choice1 = {
    56, 48, 40, 32, 24, 16, 8,  0,  57, 49, 41, 33, 25, 17,
    9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43, 35,

    62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21,
    13, 5,  60, 52, 44, 36, 28, 20, 12, 4,  27, 19, 11, 3,
};

static const key_generator_permutation_t permuted_choice2 = {
    13, 16, 10, 23, 0,  4,  2,  27, 14, 5,  20, 9,  22, 18, 11, 3,  25, 7,  15, 6,  26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
};

// These lookup tables define the number of shifts for encryption and
// decryption
static const uint8_t left_shifts[NUM_ROUNDS] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

// Expansion and permutation matrices
static const uint8_t f_expansion[ROUND_KEY_SIZE] = {
    31, 0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9,  10, 11, 12, 11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
};

static const uint8_t f_permutation[HALF_BLOCK_SIZE] = {
    15, 6, 19, 20, 28, 11, 27, 16, 0,  14, 22, 25, 4,  17, 30, 9,
    1,  7, 23, 13, 31, 26, 2,  8,  18, 12, 29, 5,  21, 10, 3,  24,
};

// S-boxes needed for the f-function
static const sbox_t sboxes[NUM_SBOXES] = {
    {
        // S box 1
        14, 0,  4,  15, 13, 7, 1,  4,  2, 14, 15, 2,  11, 13, 8,  1, 3, 10, 10, 6,  6, 12,
        12, 11, 5,  9,  9,  5, 0,  3,  7, 8,  4,  15, 1,  12, 14, 8, 8, 2,  13, 4,  6, 9,
        2,  1,  11, 7,  15, 5, 12, 11, 9, 3,  7,  14, 3,  10, 10, 0, 5, 6,  0,  13,
    },

    {
        // S box 2
        15, 3,  1,  13, 8, 4,  14, 7,  6,  15, 11, 2,  3,  8, 4, 14, 9,  12, 7,  0, 2, 1,
        13, 10, 12, 6,  0, 9,  5,  11, 10, 5,  0,  13, 14, 8, 7, 10, 11, 1,  10, 3, 4, 15,
        13, 4,  1,  2,  5, 11, 8,  6,  12, 7,  6,  12, 9,  0, 3, 5,  2,  14, 15, 9,
    },

    {
        // S box 3
        10, 13, 0,  7,  9,  0,  14, 9,  6, 3,  3,  4, 15, 6,  5,  10, 1,  2, 13, 8,  12, 5,
        7,  14, 11, 12, 4,  11, 2,  15, 8, 1,  13, 1, 6,  10, 4,  13, 9,  0, 8,  6,  15, 9,
        3,  8,  0,  7,  11, 4,  1,  15, 2, 14, 12, 3, 5,  11, 10, 5,  14, 2, 7,  12,
    },

    {
        // S box 4
        7, 13, 13, 8, 14, 11, 3, 5,  0,  6, 6,  15, 9, 0,  10, 3, 1, 4, 2,  7,  8,  2,
        5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3,  6, 15, 9,  0, 0, 6, 12, 10, 11, 1,
        7, 13, 13, 8, 15, 9,  1, 4,  3,  5, 14, 11, 5, 12, 2,  7, 8, 2, 4,  14,
    },

    {
        // S box 5
        2,  14, 12, 11, 4,  2, 1,  12, 7,  4, 10, 7,  11, 13, 6, 1,  8,  5, 5,  0, 3,  15,
        15, 10, 13, 3,  0,  9, 14, 8,  9,  6, 4,  11, 2,  8,  1, 12, 11, 7, 10, 1, 13, 14,
        7,  2,  8,  13, 15, 6, 9,  15, 12, 0, 5,  9,  6,  10, 3, 4,  0,  5, 14, 3,
    },

    {
        // S box 6
        12, 10, 1,  15, 10, 4,  15, 2,  9,  7, 2,  12, 6,  9, 8,  5, 0,  6,  13, 1,  3, 13,
        4,  14, 14, 0,  7,  11, 5,  3,  11, 8, 9,  4,  14, 3, 15, 2, 5,  12, 2,  9,  8, 5,
        12, 15, 3,  10, 7,  11, 0,  14, 4,  1, 10, 7,  1,  6, 13, 0, 11, 8,  6,  13,
    },

    {
        // S box 7
        4, 13, 11, 0, 2,  11, 14, 7, 15, 4, 0, 9,  8, 1,  13, 10, 3,  14, 12, 3,  9, 5,
        7, 12, 5,  2, 10, 15, 6,  8, 1,  6, 1, 6,  4, 11, 11, 13, 13, 8,  12, 1,  3, 4,
        7, 10, 14, 7, 10, 9,  15, 5, 6,  0, 8, 15, 0, 14, 5,  2,  9,  3,  2,  12,
    },

    {
        // S box 8
        13, 1,  2, 15, 8, 13, 4,  8,  6,  10, 15, 3, 11, 7, 1, 4,  10, 12, 9, 5,  3,  6,
        14, 11, 5, 0,  0, 14, 12, 9,  7,  2,  7,  2, 11, 1, 4, 14, 1,  7,  9, 4,  12, 10,
        14, 8,  2, 13, 0, 15, 6,  12, 10, 9,  13, 0, 15, 3, 3, 5,  5,  6,  8, 11,
    },
};

// Function prototypes

// Encrypts or decrypts a 64 bit block using  DES with a 56 bit key.
static block_t des_anycrypt(const block_t input, const des_round_keys_t *round_keys);

// Encrypts or decrypts a 64 bit block using triple DES with a 112 bit key.
static block_t tdes_anycrypt(const block_t input, const tdes_round_keys_t *round_keys);

static block_t des_round(const block_t input, const round_key_t round_key);
static half_block_t des_f(const half_block_t r, const round_key_t round_key);
static permute_block_t permute(const permute_block_t input, const permutation_t permutation,
                               const uint32_t nbits);

static key56_t expand_key(const plain_des_key_t key);
static void init_round_key_generator(round_key_generator_t *rkg, const key56_t key);
static round_key_t generate_round_key(round_key_generator_t *rkg);
static void generate_round_keys(const key56_t key, des_round_keys_t *round_keys,
                                const crypt_mode_t mode);
static inline void serialize_block(uint8_t *buf, const uint32_t base_idx, const block_t block);

static int des_stream_anycrypt(const plain_tdes_key_t key, const uint8_t *src,
                               const uint32_t src_len, uint8_t *dest, const uint32_t dest_cap,
                               const crypt_mode_t crypt_mode);
// Implementation

static block_t des_round(const block_t input, const round_key_t round_key) {
    const half_block_t r = RIGHT_HALF(input);
    const half_block_t l = LEFT_HALF(input);
    return CONCAT(r, l ^ des_f(r, round_key));
}

static half_block_t des_f(const half_block_t r, const round_key_t round_key) {
    const permute_block_t expanded_r = permute((permute_block_t)r, f_expansion, EXPANSION_SIZE);
    const permute_block_t sbox_in = expanded_r ^ round_key;

    permute_block_t sbox_out = 0;
    for (uint32_t i = 0; i < NUM_SBOXES; i++) {
        const uint32_t shamt = EXPANSION_SIZE - (i + 1) * SBOX_IDX_LEN;
        const uint32_t sbox_idx = (sbox_in >> shamt) & SBOX_IDX_MASK;
        sbox_out |= sboxes[i][sbox_idx] << shamt;
    }

    return (half_block_t)permute(sbox_out, f_permutation, HALF_BLOCK_SIZE);
}

static permute_block_t permute(const permute_block_t input, const permutation_t permutation,
                               const uint32_t nbits) {
    block_t output = 0;

    for (uint32_t i = 0; i < nbits; i++) {
        const uint32_t pos = permutation[i];
        const block_t bit = (input & BIT_AT(pos)) >> pos;
        output |= bit << i;
    }

    return output;
}

static key56_t expand_key(const plain_des_key_t key) {
    key56_t expanded_key = 0;

    for (uint32_t i = 0; i <= KEY_SIZE / 8; i++) {
        uint64_t key_bits = ((key >> (i * 7)) & (BIT_AT(7) - 1));
        key_bits |= ~(PARITY_MASK(key_bits & 0xf) ^ PARITY_MASK((key_bits >> 4) & 0xf)) & BIT_AT(7);
        expanded_key |= key_bits << (i * 8);
    }

    return expanded_key;
}

static void init_round_key_generator(round_key_generator_t *rkg, const key56_t key) {
    const permute_block_t pc1 = permute((permute_block_t)key, permuted_choice1, KEY_SIZE);
    rkg->c = CX(pc1);
    rkg->d = DX(pc1);
    rkg->round = 0;
}

static void generate_round_keys(const key56_t key, des_round_keys_t *round_keys,
                                const crypt_mode_t crypt_mode) {
    round_key_generator_t rkg;
    init_round_key_generator(&rkg, key);
    for (uint32_t round = 0; round < NUM_ROUNDS; round++) {
        (*round_keys)[ROUND_INDEX(round, crypt_mode)] = generate_round_key(&rkg);
    }
}

static round_key_t generate_round_key(round_key_generator_t *rkg) {
    const uint8_t shamt = left_shifts[rkg->round];
    rkg->c = KEY_DERIV_LEFT_ROTATE(rkg->c, shamt);
    rkg->d = KEY_DERIV_LEFT_ROTATE(rkg->d, shamt);
    rkg->round++;
    const permute_block_t cd = STACK_CD(rkg->c, rkg->d);
    return (round_key_t)permute(cd, permuted_choice2, ROUND_KEY_SIZE);
}

static inline void serialize_block(uint8_t *buf, const uint32_t base_idx, const block_t block) {
    for (uint32_t i = 0; i < BLOCK_SIZE_BYTES; i++) {
        buf[base_idx + i] = (block >> ((BLOCK_SIZE_BYTES - i - 1) * 8)) & 0xff;
    }
}

static block_t des_anycrypt(const block_t input, const des_round_keys_t *round_keys) {
    const block_t permuted_block = permute(input, ip, BLOCK_SIZE);
    block_t intermediate_result = permuted_block;

    for (uint32_t round = 0; round < NUM_ROUNDS; round++) {
        const round_key_t round_key = (*round_keys)[round];
        intermediate_result = des_round(intermediate_result, round_key);
    }

    // We do not want to swap left and right in the last round so we swap it back.
    return permute(SWAP_LR(intermediate_result), ipinv, BLOCK_SIZE);
}

static block_t tdes_anycrypt(const block_t input, const tdes_round_keys_t *round_keys) {
    const block_t w1 = des_anycrypt(input, &((*round_keys)[0]));
    const block_t w2 = des_anycrypt(w1, &((*round_keys)[1]));
    return des_anycrypt(w2, &((*round_keys)[0]));
}

static int des_stream_anycrypt(const plain_tdes_key_t key, const uint8_t *src,
                               const uint32_t src_len, uint8_t *dest, const uint32_t dest_cap,
                               const crypt_mode_t crypt_mode) {
    const uint32_t dest_len =
        src_len + ((BLOCK_SIZE_BYTES - (src_len & BLOCK_ADDR_MASK)) & BLOCK_ADDR_MASK);
    const uint32_t padding = dest_len - src_len;
    if (dest_len > dest_cap)
        return -1;

    const key112_t expanded_key = {expand_key(key[0]), expand_key(key[1])};
    tdes_round_keys_t round_keys;
    generate_round_keys(expanded_key[0], &round_keys[0], crypt_mode);
    generate_round_keys(expanded_key[1], &round_keys[1], INVERSE_CRYPT_MODE(crypt_mode));

    block_t block = 0;
    for (uint32_t i = 0; i < (src_len & ~BLOCK_ADDR_MASK); i++) {
        block = (block << 8) | src[i];

        if ((i & BLOCK_ADDR_MASK) != BLOCK_SIZE_BYTES - 1)
            continue;

        const block_t encrypted_block =
            tdes_anycrypt(block, (const tdes_round_keys_t *)&round_keys);
        serialize_block(dest, i & ~BLOCK_ADDR_MASK, encrypted_block);
        block = 0;
    }

    if (padding > 0) {
        for (uint32_t i = (src_len & ~BLOCK_ADDR_MASK); i < src_len; i++) {
            block = (block << 8) | src[i];
        }
        for (uint32_t i = 0; i < padding; i++) {
            block = (block << 8) | padding;
        }
        const block_t encrypted_block =
            tdes_anycrypt(block, (const tdes_round_keys_t *)&round_keys);
        serialize_block(dest, src_len & ~BLOCK_ADDR_MASK, encrypted_block);
    }

    return dest_len;
}

/************************************************************************/
/*                          Public functions                            */
/************************************************************************/

int des_stream_encrypt(const plain_des_key_t key, const uint8_t *stream, const uint32_t length,
                       uint8_t *cipherstream, const uint32_t ciphercap) {
    return des_stream_anycrypt((plain_tdes_key_t){key, key}, stream, length, cipherstream,
                               ciphercap, CRYPT_MODE_ENCRYPT);
}

int des_stream_decrypt(const plain_des_key_t key, const uint8_t *cipherstream,
                       const uint32_t length, uint8_t *stream, const uint32_t streamcap) {
    // Buffer to decrypt must have a size equal to a multiple of block size!
    if ((length & BLOCK_ADDR_MASK) != 0) {
        return -2;
    }

    return des_stream_anycrypt((plain_tdes_key_t){key, key}, cipherstream, length, stream,
                               streamcap, CRYPT_MODE_DECRYPT);
}

int tdes_stream_encrypt(const plain_tdes_key_t key, const uint8_t *stream, const uint32_t length,
                        uint8_t *cipherstream, const uint32_t ciphercap) {
    return des_stream_anycrypt(key, stream, length, cipherstream, ciphercap, CRYPT_MODE_ENCRYPT);
}

int tdes_stream_decrypt(const plain_tdes_key_t key, const uint8_t *cipherstream,
                        const uint32_t length, uint8_t *stream, const uint32_t streamcap) {
    // Buffer to decrypt must have a size equal to a multiple of block size!
    if ((length & BLOCK_ADDR_MASK) != 0) {
        return -2;
    }

    return des_stream_anycrypt(key, cipherstream, length, stream, streamcap, CRYPT_MODE_DECRYPT);
}
