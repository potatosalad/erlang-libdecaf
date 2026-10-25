#ifndef LIBDECAF_NIF_TUAK_PRIMITIVE_H
#define LIBDECAF_NIF_TUAK_PRIMITIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned mac_length, res_length, ck_length, ik_length;
    uint32_t iterations;
} libdecaf_nif_tuak_options_t;

typedef struct {
    uint8_t res[32], ck[32], ik[32], ak[6];
} libdecaf_nif_tuak_outputs_t;

/* Byte storage is safe inside a NIF resource; permutations use an aligned local state. */
extern void libdecaf_nif_tuak_prepare(uint8_t state[200], const uint8_t *key, size_t key_length, const uint8_t top[32],
                                      uint8_t instance, const uint8_t *rand, const uint8_t *sqn, const uint8_t *amf);
extern void libdecaf_nif_tuak_iterate(uint8_t state[200], uint32_t iterations);
extern void libdecaf_nif_tuak_extract(const uint8_t state[200], size_t offset, uint8_t *output, size_t length);

extern void libdecaf_nif_tuak_topc_compute(const uint8_t *key, size_t key_length, const uint8_t top[32], uint32_t iterations,
                                           uint8_t topc[32]);
extern void libdecaf_nif_tuak_f1_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                                         const uint8_t sqn[6], const uint8_t amf[2], const libdecaf_nif_tuak_options_t *options,
                                         uint8_t *mac);
extern void libdecaf_nif_tuak_f1_star_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                                              const uint8_t sqn[6], const uint8_t amf[2],
                                              const libdecaf_nif_tuak_options_t *options, uint8_t *mac);
extern void libdecaf_nif_tuak_f2345_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                                            const libdecaf_nif_tuak_options_t *options, libdecaf_nif_tuak_outputs_t *outputs);
extern void libdecaf_nif_tuak_f5_star_compute(const uint8_t *key, size_t key_length, const uint8_t topc[32], const uint8_t rand[16],
                                              uint32_t iterations, uint8_t ak[6]);

#ifdef __cplusplus
}
#endif

#endif
