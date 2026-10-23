#ifndef LIBDECAF_NIF_ED448_H
#define LIBDECAF_NIF_ED448_H

#include "../libdecaf_nif.h"

#include <decaf/ed448.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libdecaf_nif_ed448_keypair_s libdecaf_nif_ed448_keypair_t;

struct libdecaf_nif_ed448_keypair_s {
    decaf_eddsa_448_keypair_t inner;
};

int libdecaf_nif_ed448_load(ErlNifEnv *env);

extern ERL_NIF_TERM libdecaf_nif_ed448_derive_keypair_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed448_keypair_extract_private_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed448_keypair_extract_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed448_keypair_sign_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed448_keypair_sign_prehash_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM libdecaf_nif_ed448_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM libdecaf_nif_ed448_sign_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM libdecaf_nif_ed448_sign_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM libdecaf_nif_ed448_verify_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM libdecaf_nif_ed448_verify_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM libdecaf_nif_ed448_convert_public_key_to_x448_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM libdecaf_nif_ed448_convert_private_key_to_x448_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif
