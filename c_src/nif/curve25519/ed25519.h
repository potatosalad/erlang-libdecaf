#ifndef LIBDECAF_NIF_ED25519_H
#define LIBDECAF_NIF_ED25519_H

#include "../libdecaf_nif.h"

#include <decaf/ed255.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libdecaf_nif_ed25519_keypair_s libdecaf_nif_ed25519_keypair_t;

struct libdecaf_nif_ed25519_keypair_s {
    decaf_eddsa_25519_keypair_t inner;
};

extern int libdecaf_nif_ed25519_load(ErlNifEnv *env);
extern libdecaf_nif_ed25519_keypair_t *
libdecaf_nif_ed25519_keypair_from_secret(const uint8_t secret[DECAF_EDDSA_25519_PRIVATE_BYTES]);
extern libdecaf_nif_ed25519_keypair_t *libdecaf_nif_ed25519_get_keypair(ErlNifEnv *env, ERL_NIF_TERM term);

extern ERL_NIF_TERM libdecaf_nif_ed25519_derive_keypair_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_keypair_extract_private_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_keypair_extract_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_keypair_sign_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_keypair_sign_prehash_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

extern ERL_NIF_TERM libdecaf_nif_ed25519_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_sign_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_sign_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_verify_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_verify_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_convert_public_key_to_x25519_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519_convert_private_key_to_x25519_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif
