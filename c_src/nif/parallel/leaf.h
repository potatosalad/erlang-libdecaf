#ifndef LIBDECAF_NIF_PARALLEL_LEAF_H
#define LIBDECAF_NIF_PARALLEL_LEAF_H

#include "algorithm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void libdecaf_nif_parallel_leaf_hash(libdecaf_nif_parallel_leaf_t algorithm, const uint8_t *input, size_t length,
                                            uint8_t *chaining);
extern unsigned int libdecaf_nif_parallel_leaf_width(void);
extern void libdecaf_nif_parallel_leaf_hash_many(libdecaf_nif_parallel_leaf_t algorithm, const uint8_t *const *inputs,
                                                 size_t length, uint8_t *const *chaining, unsigned int width);

#ifdef __cplusplus
}
#endif

#endif
