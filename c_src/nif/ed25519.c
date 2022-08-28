// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "ed25519.h"

/* Function Definitions */

/* libdecaf_nif:ed25519_derive_keypair/1 */

ERL_NIF_TERM
libdecaf_nif_ed25519_derive_keypair_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM out_term;
    ErlNifBinary privkey;
    libdecaf_nif_ed25519_keypair_t *keypair = NULL;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }

    if (!enif_inspect_binary(env, argv[0], &privkey) || privkey.size != DECAF_EDDSA_25519_PRIVATE_BYTES) {
        return EXCP_BADARG_F(env, "Privkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PRIVATE_BYTES);
    }

    keypair = (libdecaf_nif_ed25519_keypair_t *)(enif_alloc_resource(libdecaf_nif_ed25519_keypair_resource_type, sizeof(libdecaf_nif_ed25519_keypair_t)));
    if (keypair == NULL) {
        return EXCP_ERROR(env, "Failed to allocate libdecaf_nif_ed25519_keypair_t");
    }
    (void)decaf_ed25519_derive_keypair(keypair->inner, privkey.data);

    out_term = enif_make_resource(env, (void *)keypair);
    (void)enif_release_resource((void *)keypair);

    return out_term;
}

/* libdecaf_nif:ed25519_keypair_extract_private_key/1 */

ERL_NIF_TERM
libdecaf_nif_ed25519_keypair_extract_private_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519_keypair_t *keypair = NULL;
    ERL_NIF_TERM out;
    uint8_t *privkey = NULL;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_ed25519_keypair_resource_type, (void **)(&keypair))) {
        return EXCP_BADARG(env, "Keypair reference is invalid");
    }

    privkey = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_25519_PRIVATE_BYTES, &out));
    (void)decaf_ed25519_keypair_extract_private_key(privkey, keypair->inner);

    return out;
}

/* libdecaf_nif:ed25519_keypair_extract_public_key/1 */

ERL_NIF_TERM
libdecaf_nif_ed25519_keypair_extract_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519_keypair_t *keypair = NULL;
    ERL_NIF_TERM out;
    uint8_t *pubkey = NULL;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_ed25519_keypair_resource_type, (void **)(&keypair))) {
        return EXCP_BADARG(env, "Keypair reference is invalid");
    }

    pubkey = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_25519_PUBLIC_BYTES, &out));
    (void)decaf_ed25519_keypair_extract_public_key(pubkey, keypair->inner);

    return out;
}

/* libdecaf_nif:ed25519_keypair_sign/4 */

ERL_NIF_TERM
libdecaf_nif_ed25519_keypair_sign_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519_keypair_t *keypair = NULL;
    ErlNifBinary message;
    unsigned int prehashed;
    ErlNifBinary context;
    ERL_NIF_TERM out;
    uint8_t *signature = NULL;

    if (argc != 4) {
        return EXCP_BADARG(env, "argc must be 4");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_ed25519_keypair_resource_type, (void **)(&keypair))) {
        return EXCP_BADARG(env, "Keypair reference is invalid");
    }
    if (!enif_inspect_binary(env, argv[1], &message)) {
        return EXCP_BADARG(env, "Message must be a binary");
    }
    if (!enif_get_uint(env, argv[2], &prehashed) || (prehashed != 0 && prehashed != 1)) {
        return EXCP_BADARG(env, "Prehashed must be one of {0,1}");
    }
    if (enif_compare(ATOM(no_context), argv[3]) == 0) {
        context.size = 0;
        context.data = (unsigned char *)(DECAF_ED25519_NO_CONTEXT);
    } else if (!enif_inspect_binary(env, argv[3], &context) || context.size > 255) {
        return EXCP_BADARG(env, "Context must be either the atom 'no_context' or a binary of size <= 255-bytes");
    }

    signature = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_25519_SIGNATURE_BYTES, &out));
    (void)decaf_ed25519_keypair_sign(signature, keypair->inner, message.data, message.size, prehashed, context.data, context.size);

    return out;
}

/* libdecaf_nif:ed25519_keypair_sign_prehash/3 */

ERL_NIF_TERM
libdecaf_nif_ed25519_keypair_sign_prehash_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519_keypair_t *keypair = NULL;
    ErlNifBinary message;
    ErlNifBinary context;
    decaf_ed25519_prehash_ctx_t hash;
    ERL_NIF_TERM out;
    uint8_t *signature = NULL;

    if (argc != 3) {
        return EXCP_BADARG(env, "argc must be 3");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_ed25519_keypair_resource_type, (void **)(&keypair))) {
        return EXCP_BADARG(env, "Keypair reference is invalid");
    }
    if (!enif_inspect_binary(env, argv[1], &message)) {
        return EXCP_BADARG(env, "Message must be a binary");
    }
    if (enif_compare(ATOM(no_context), argv[2]) == 0) {
        context.size = 0;
        context.data = (unsigned char *)(DECAF_ED25519_NO_CONTEXT);
    } else if (!enif_inspect_binary(env, argv[2], &context) || context.size > 255) {
        return EXCP_BADARG(env, "Context must be either the atom 'no_context' or a binary of size <= 255-bytes");
    }

    (void)decaf_ed25519_prehash_init(hash);
    (void)decaf_ed25519_prehash_update(hash, message.data, message.size);
    signature = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_25519_SIGNATURE_BYTES, &out));
    (void)decaf_ed25519_keypair_sign_prehash(signature, keypair->inner, hash, context.data, context.size);
    (void)decaf_ed25519_prehash_destroy(hash);

    return out;
}
