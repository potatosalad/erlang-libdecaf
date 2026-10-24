#ifndef LIBDECAF_NIF_PARALLEL_H
#define LIBDECAF_NIF_PARALLEL_H

#include "../libdecaf_nif.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int libdecaf_nif_parallel_load(ErlNifEnv *env);
extern ERL_NIF_TERM libdecaf_nif_parallel_absorb_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_parallel_router_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif
