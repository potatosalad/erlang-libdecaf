#ifndef LIBDECAF_NIF_PARALLEL_ALGORITHM_H
#define LIBDECAF_NIF_PARALLEL_ALGORITHM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t rate;
    bool turbo;
} libdecaf_nif_parallel_leaf_t;

typedef struct {
    size_t (*block_size)(const void *context);
    size_t (*prefix)(const void *context);
    libdecaf_nif_parallel_leaf_t (*leaf)(const void *context);
    void (*update)(void *context, const uint8_t *input, size_t length);
    bool (*join)(void *context, const uint8_t *chaining_value);
} libdecaf_nif_parallel_algorithm_t;

#ifdef __cplusplus
}
#endif

#endif
