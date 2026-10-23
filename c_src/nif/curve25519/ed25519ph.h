#ifndef LIBDECAF_NIF_ED25519PH_H
#define LIBDECAF_NIF_ED25519PH_H

#include "../libdecaf_nif.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int libdecaf_nif_ed25519ph_load(ErlNifEnv *env);

extern ERL_NIF_TERM libdecaf_nif_ed25519ph_sign_init_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_keypair_sign_init_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_sign_init_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_keypair_sign_init_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_sign_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_sign_final_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_verify_init_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_verify_init_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_verify_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_ed25519ph_verify_final_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif
