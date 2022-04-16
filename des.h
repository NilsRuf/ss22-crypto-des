/*
    @file des.c
    @author Nils Ruf

    This header file exposes the functions to encrypt and decrypt messages with DES and triple DES
   using CMB paddig mode.
*/

#ifndef _DES_H_
#define _DES_H_

#include <stdint.h>

// DES key type (seven bytes)
typedef uint64_t plain_des_key_t;
// Triple DES key type (14 bytes)
typedef uint64_t plain_tdes_key_t[2];

int des_stream_encrypt(const plain_des_key_t key, const uint8_t *stream, const uint32_t length,
                       uint8_t *cipherstream, const uint32_t ciphercap);

int des_stream_decrypt(const plain_des_key_t key, const uint8_t *cipherstream,
                       const uint32_t length, uint8_t *stream, const uint32_t streamcap);

int tdes_stream_encrypt(const plain_tdes_key_t key, const uint8_t *stream, const uint32_t length,
                        uint8_t *cipherstream, const uint32_t ciphercap);

int tdes_stream_decrypt(const plain_tdes_key_t key, const uint8_t *cipherstream,
                        const uint32_t length, uint8_t *stream, const uint32_t streamcap);
#endif
