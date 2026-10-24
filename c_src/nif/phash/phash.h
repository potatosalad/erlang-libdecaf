#ifndef LIBDECAF_NIF_PHASH_H
#define LIBDECAF_NIF_PHASH_H

#include "../libdecaf_nif.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int libdecaf_nif_phash_load(ErlNifEnv *env);
extern ERL_NIF_TERM libdecaf_nif_phash_worker_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif
