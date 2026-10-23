#ifndef LIBDECAF_NIF_X448_H
#define LIBDECAF_NIF_X448_H

#include "../libdecaf_nif.h"
#include <decaf/point_448.h>

#ifdef __cplusplus
extern "C" {
#endif

ERL_NIF_TERM libdecaf_nif_x448_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM libdecaf_nif_x448_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif
