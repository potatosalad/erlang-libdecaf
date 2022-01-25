// -*- mode: c++; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c++ et

#ifndef LIBDECAF_NIF_CSPRNG_H
#define LIBDECAF_NIF_CSPRNG_H

#include "libdecaf_nif.h"

#include <decaf/spongerng.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libdecaf_nif_csprng_ctx_s libdecaf_nif_csprng_ctx_t;

struct libdecaf_nif_csprng_ctx_s {
    decaf_keccak_prng_s state;
};

extern ERL_NIF_TERM libdecaf_nif_spongerng_csprng_init_from_buffer_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_spongerng_csprng_init_from_file_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_spongerng_csprng_init_from_dev_urandom_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_spongerng_csprng_next_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_spongerng_csprng_stir_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif
