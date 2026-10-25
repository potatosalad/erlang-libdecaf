/**
 * @cond internal
 * @file shake.c
 * @copyright
 *   Uses public domain code by Mathias Panzenböck \n
 *   Uses CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#define _BSD_SOURCE 1 /* for endian */
#define _DEFAULT_SOURCE 1 /* for endian with glibc 2.20 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "portable_endian.h"
#include "keccak_internal.h"
#include <decaf/shake.h>

#define FLAG_ABSORBING 'A'
#define FLAG_SQUEEZING 'Z'

decaf_error_t decaf_sha3_update (
    struct decaf_keccak_sponge_s * __restrict__ decaf_sponge,
    const uint8_t *in,
    size_t len
) {
    assert(decaf_sponge->params->position < decaf_sponge->params->rate);
    assert(decaf_sponge->params->rate < sizeof(decaf_sponge->state));
    assert(decaf_sponge->params->flags == FLAG_ABSORBING);
    while (len) {
        if (decaf_sponge->params->position == 0 && decaf_sponge->params->rate % 8 == 0 && len >= decaf_sponge->params->rate) {
            size_t consumed = decaf_keccak_absorb_blocks(decaf_sponge->state, decaf_sponge->params->rate,
                decaf_sponge->params->start_round, in, len);
            in += consumed;
            len -= consumed;
            if (len == 0) break;
        }
        size_t cando = decaf_sponge->params->rate - decaf_sponge->params->position, i;
        uint8_t* state = &decaf_sponge->state->b[decaf_sponge->params->position];
        if (cando > len) {
            for (i = 0; i < len; i += 1) state[i] ^= in[i];
            decaf_sponge->params->position += (uint8_t)len;
            break;
        } else {
            for (i = 0; i < cando; i += 1) state[i] ^= in[i];
            dokeccak(decaf_sponge);
            len -= cando;
            in += cando;
        }
    }
    return (decaf_sponge->params->flags == FLAG_ABSORBING) ? DECAF_SUCCESS : DECAF_FAILURE;
}

decaf_error_t decaf_sha3_output (
    decaf_keccak_sponge_t decaf_sponge,
    uint8_t * __restrict__ out,
    size_t len
) {
    decaf_error_t ret = DECAF_SUCCESS;
    assert(decaf_sponge->params->position < decaf_sponge->params->rate);
    assert(decaf_sponge->params->rate < sizeof(decaf_sponge->state));
    
    if (decaf_sponge->params->max_out != 0xFF) {
        if (decaf_sponge->params->remaining >= len) {
            decaf_sponge->params->remaining -= (uint8_t)len;
        } else {
            decaf_sponge->params->remaining = 0;
            ret = DECAF_FAILURE;
        }
    }
    
    switch (decaf_sponge->params->flags) {
    case FLAG_SQUEEZING: break;
    case FLAG_ABSORBING:
        {
            uint8_t* state = decaf_sponge->state->b;
            state[decaf_sponge->params->position] ^= decaf_sponge->params->pad;
            state[decaf_sponge->params->rate - 1] ^= decaf_sponge->params->rate_pad;
            dokeccak(decaf_sponge);
            decaf_sponge->params->flags = FLAG_SQUEEZING;
            break;
        }
    default:
        assert(0);
    }
    
    while (len) {
        size_t cando = decaf_sponge->params->rate - decaf_sponge->params->position;
        uint8_t* state = &decaf_sponge->state->b[decaf_sponge->params->position];
        if (cando > len) {
            memcpy(out, state, len);
            decaf_sponge->params->position += (uint8_t)len;
            return ret;
        } else {
            memcpy(out, state, cando);
            dokeccak(decaf_sponge);
            len -= cando;
            out += cando;
        }
    }
    return ret;
}

decaf_error_t decaf_sha3_final (
    decaf_keccak_sponge_t decaf_sponge,
    uint8_t * __restrict__ out,
    size_t len
) {
    decaf_error_t ret = decaf_sha3_output(decaf_sponge,out,len);
    decaf_sha3_reset(decaf_sponge);
    return ret;
}

void decaf_sha3_reset (
    decaf_keccak_sponge_t decaf_sponge
) {
    decaf_sha3_init(decaf_sponge, decaf_sponge->params);
    decaf_sponge->params->flags = FLAG_ABSORBING;
    decaf_sponge->params->remaining = decaf_sponge->params->max_out;
}

void decaf_sha3_destroy (decaf_keccak_sponge_t decaf_sponge) {
    decaf_bzero(decaf_sponge, sizeof(decaf_keccak_sponge_t));
}

void decaf_sha3_init (
    decaf_keccak_sponge_t decaf_sponge,
    const struct decaf_kparams_s *params
) {
    decaf_bzero(decaf_sponge->state, sizeof(decaf_sponge->state));
    decaf_sponge->params[0] = params[0];
    decaf_sponge->params->position = 0;
}

decaf_error_t decaf_sha3_hash (
    uint8_t *out,
    size_t outlen,
    const uint8_t *in,
    size_t inlen,
    const struct decaf_kparams_s *params
) {
    decaf_keccak_sponge_t decaf_sponge;
    decaf_sha3_init(decaf_sponge, params);
    decaf_sha3_update(decaf_sponge, in, inlen);
    decaf_error_t ret = decaf_sha3_output(decaf_sponge, out, outlen);
    decaf_sha3_destroy(decaf_sponge);
    return ret;
}

#define DEFSHAKE(n) \
    const struct decaf_kparams_s DECAF_SHAKE##n##_params_s = \
        { 0, FLAG_ABSORBING, 200-n/4, 0, 0x1f, 0x80, 0xFF, 0xFF };
    
#define DEFSHA3(n) \
    const struct decaf_kparams_s DECAF_SHA3_##n##_params_s = \
        { 0, FLAG_ABSORBING, 200-n/4, 0, 0x06, 0x80, n/8, n/8 };

size_t decaf_sha3_default_output_bytes (
    const decaf_keccak_sponge_t s
) {
    return (s->params->max_out == 0xFF)
        ? (200-s->params->rate)
        : ((200-s->params->rate)/2);
}

size_t decaf_sha3_max_output_bytes (
    const decaf_keccak_sponge_t s
) {
    return (s->params->max_out == 0xFF)
        ? SIZE_MAX
        : (size_t)((200-s->params->rate)/2);
}

DEFSHAKE(128)
DEFSHAKE(256)
DEFSHA3(224)
DEFSHA3(256)
DEFSHA3(384)
DEFSHA3(512)

/* FUTURE: Keyak instances, etc */
