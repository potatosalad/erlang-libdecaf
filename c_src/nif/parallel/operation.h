#ifndef LIBDECAF_NIF_PARALLEL_OPERATION_H
#define LIBDECAF_NIF_PARALLEL_OPERATION_H

#include "../libdecaf_nif.h"
#include "algorithm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libdecaf_nif_parallel_operation_s libdecaf_nif_parallel_operation_t;

extern ErlNifResourceType *libdecaf_nif_parallel_operation_load(ErlNifEnv *env, const char *name);
extern libdecaf_nif_parallel_operation_t *libdecaf_nif_parallel_operation_create(ErlNifEnv *env, ErlNifResourceType *type,
                                                                                 ERL_NIF_TERM state, ERL_NIF_TERM input,
                                                                                 size_t block_size,
                                                                                 libdecaf_nif_parallel_leaf_t leaf, bool finish,
                                                                                 size_t output_length, ERL_NIF_TERM *error);
extern libdecaf_nif_parallel_operation_t *libdecaf_nif_parallel_operation_get(ErlNifEnv *env, ErlNifResourceType *type,
                                                                              ERL_NIF_TERM term);
extern ERL_NIF_TERM libdecaf_nif_parallel_operation_state(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation);
extern void libdecaf_nif_parallel_operation_abort(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation);
extern ERL_NIF_TERM libdecaf_nif_parallel_operation_result(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation,
                                                           ERL_NIF_TERM state);
/* Returns 1 when finished, 0 awaiting work, 2 to yield bounded root collection,
 * 3 for dirty scheduler fallback, or -1 on an invalid/overflowed context. */
extern int libdecaf_nif_parallel_operation_step(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation, void *context,
                                                const libdecaf_nif_parallel_algorithm_t *algorithm);
extern ERL_NIF_TERM libdecaf_nif_parallel_operation_await(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation);

#ifdef __cplusplus
}
#endif

#endif
