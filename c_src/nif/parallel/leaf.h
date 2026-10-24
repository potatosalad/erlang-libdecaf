#ifndef LIBDECAF_NIF_PARALLEL_LEAF_H
#define LIBDECAF_NIF_PARALLEL_LEAF_H

#include "algorithm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void libdecaf_nif_parallel_leaf_hash(libdecaf_nif_parallel_leaf_t algorithm, const uint8_t *input, size_t length,
                                            uint8_t *chaining);
extern void libdecaf_nif_parallel_leaf_hash2(libdecaf_nif_parallel_leaf_t algorithm, const uint8_t *input0, const uint8_t *input1,
                                             size_t length, uint8_t *chaining0, uint8_t *chaining1);

#ifdef __cplusplus
}
#endif

#endif
