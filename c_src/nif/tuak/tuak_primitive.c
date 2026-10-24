#include <keccak_internal.h>
#include <decaf/common.h>
#include "tuak_primitive.h"

/* TS 35.231 maps each external byte string in reverse byte order into the
 * Keccak state. The permutation operates on its usual little-endian lanes. */
static void
libdecaf_nif_tuak_reverse(uint8_t *output, const uint8_t *input, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        output[i] = input[length - 1 - i];
}

static void
libdecaf_nif_tuak_evaluate(kdomain_t state, const uint8_t *key, size_t key_length, const uint8_t top[32], uint8_t instance,
                           const uint8_t *rand, const uint8_t *sqn, const uint8_t *amf, uint32_t iterations)
{
    static const uint8_t algorithm[] = "TUAK1.0";
    decaf_bzero(state, sizeof(kdomain_t));
    libdecaf_nif_tuak_reverse(state->b, top, 32);
    state->b[32] = instance | (key_length == 32 ? 1 : 0);
    libdecaf_nif_tuak_reverse(state->b + 33, algorithm, 7);
    if (rand != NULL)
        libdecaf_nif_tuak_reverse(state->b + 40, rand, 16);
    if (amf != NULL)
        libdecaf_nif_tuak_reverse(state->b + 56, amf, 2);
    if (sqn != NULL)
        libdecaf_nif_tuak_reverse(state->b + 58, sqn, 6);
    libdecaf_nif_tuak_reverse(state->b + 64, key, key_length);
    state->b[96] = 0x1F;
    state->b[135] = 0x80;
    for (uint32_t i = 0; i < iterations; ++i)
        keccakf(state, 0);
}

void
libdecaf_nif_tuak_topc_compute(const uint8_t *key, size_t key_length, const uint8_t top[32], uint32_t iterations, uint8_t topc[32])
{
    kdomain_t state;
    libdecaf_nif_tuak_evaluate(state, key, key_length, top, 0, NULL, NULL, NULL, iterations);
    libdecaf_nif_tuak_reverse(topc, state->b, 32);
    decaf_bzero(state, sizeof(state));
}

void
libdecaf_nif_tuak_f1_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                             const uint8_t sqn[6], const uint8_t amf[2], const libdecaf_nif_tuak_options_t *options, uint8_t *mac)
{
    kdomain_t state;
    libdecaf_nif_tuak_evaluate(state, key, key_length, topc, (uint8_t)options->mac_length, rand, sqn, amf, options->iterations);
    libdecaf_nif_tuak_reverse(mac, state->b, options->mac_length);
    decaf_bzero(state, sizeof(state));
}

void
libdecaf_nif_tuak_f1_star_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                                  const uint8_t sqn[6], const uint8_t amf[2], const libdecaf_nif_tuak_options_t *options,
                                  uint8_t *mac)
{
    kdomain_t state;
    libdecaf_nif_tuak_evaluate(state, key, key_length, topc, (uint8_t)(options->mac_length | 0x80), rand, sqn, amf,
                               options->iterations);
    libdecaf_nif_tuak_reverse(mac, state->b, options->mac_length);
    decaf_bzero(state, sizeof(state));
}

void
libdecaf_nif_tuak_f2345_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                                const libdecaf_nif_tuak_options_t *options, libdecaf_nif_tuak_outputs_t *outputs)
{
    kdomain_t state;
    uint8_t instance =
        (uint8_t)(0x40 | (options->res_length & 0x38) | ((options->ck_length >> 3) & 0x04) | ((options->ik_length >> 4) & 0x02));
    libdecaf_nif_tuak_evaluate(state, key, key_length, topc, instance, rand, NULL, NULL, options->iterations);
    libdecaf_nif_tuak_reverse(outputs->res, state->b, options->res_length);
    libdecaf_nif_tuak_reverse(outputs->ck, state->b + 32, options->ck_length);
    libdecaf_nif_tuak_reverse(outputs->ik, state->b + 64, options->ik_length);
    libdecaf_nif_tuak_reverse(outputs->ak, state->b + 96, 6);
    decaf_bzero(state, sizeof(state));
}

void
libdecaf_nif_tuak_f5_star_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                                  uint32_t iterations, uint8_t ak[6])
{
    kdomain_t state;
    libdecaf_nif_tuak_evaluate(state, key, key_length, topc, 0xC0, rand, NULL, NULL, iterations);
    libdecaf_nif_tuak_reverse(ak, state->b + 96, 6);
    decaf_bzero(state, sizeof(state));
}
