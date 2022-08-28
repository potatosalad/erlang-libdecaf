// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include <decaf/ed255.h>

/*
 * Erlang NIF functions
 */

/* libdecaf_nif:ed25519_derive_public_key/1 */

static ERL_NIF_TERM
libdecaf_nif_ed25519_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary privkey;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }

    if (!enif_inspect_binary(env, argv[0], &privkey) || privkey.size != DECAF_EDDSA_25519_PRIVATE_BYTES) {
        return EXCP_BADARG_F(env, "Privkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PRIVATE_BYTES);
    }

    ERL_NIF_TERM out;
    uint8_t *pubkey = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_25519_PUBLIC_BYTES, &out));

    (void)decaf_ed25519_derive_public_key(pubkey, privkey.data);

    return out;
}

/* libdecaf_nif:ed25519_sign/5 */

static ERL_NIF_TERM
libdecaf_nif_ed25519_sign_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary privkey;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    unsigned int prehashed;
    ErlNifBinary context;
    decaf_eddsa_25519_keypair_t keypair;
    uint8_t rederived_pubkey[DECAF_EDDSA_25519_PUBLIC_BYTES];
    ERL_NIF_TERM out;
    uint8_t *signature = NULL;

    if (argc != 5) {
        return EXCP_BADARG(env, "argc must be 5");
    }

    if (!enif_inspect_binary(env, argv[0], &privkey) || privkey.size != DECAF_EDDSA_25519_PRIVATE_BYTES) {
        return EXCP_BADARG_F(env, "Privkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PRIVATE_BYTES);
    }
    if (!enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_25519_PUBLIC_BYTES) {
        return EXCP_BADARG_F(env, "Pubkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PUBLIC_BYTES);
    }
    if (!enif_inspect_binary(env, argv[2], &message)) {
        return EXCP_BADARG(env, "Message must be a binary");
    }
    if (!enif_get_uint(env, argv[3], &prehashed) || (prehashed != 0 && prehashed != 1)) {
        return EXCP_BADARG(env, "Prehashed must be one of {0,1}");
    }
    if (enif_compare(ATOM(no_context), argv[4]) == 0) {
        context.size = 0;
        context.data = (unsigned char *)(DECAF_ED25519_NO_CONTEXT);
    } else if (!enif_inspect_binary(env, argv[4], &context) || context.size > 255) {
        return EXCP_BADARG(env, "Context must be either the atom 'no_context' or a binary of size <= 255-bytes");
    }

    (void)decaf_ed25519_derive_keypair(keypair, privkey.data);
    (void)decaf_ed25519_keypair_extract_public_key(rederived_pubkey, keypair);
    if (decaf_memeq(rederived_pubkey, pubkey.data, sizeof(rederived_pubkey)) != DECAF_TRUE) {
        return EXCP_ERROR(env, "UNSAFE: Privkey and Pubkey are not part of the same keypair. See: https://github.com/MystenLabs/ed25519-unsafe-libs");
    }
    signature = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_25519_SIGNATURE_BYTES, &out));
    (void)decaf_ed25519_keypair_sign(signature, keypair, message.data, message.size, prehashed, context.data, context.size);
    (void)decaf_ed25519_keypair_destroy(keypair);

    return out;
}

/* libdecaf_nif:ed25519_sign_prehash/4 */

static ERL_NIF_TERM
libdecaf_nif_ed25519_sign_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary privkey;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    ErlNifBinary context;
    decaf_eddsa_25519_keypair_t keypair;
    uint8_t rederived_pubkey[DECAF_EDDSA_25519_PUBLIC_BYTES];
    decaf_ed25519_prehash_ctx_t hash;
    ERL_NIF_TERM out;
    uint8_t *signature = NULL;

    if (argc != 4) {
        return EXCP_BADARG(env, "argc must be 4");
    }

    if (!enif_inspect_binary(env, argv[0], &privkey) || privkey.size != DECAF_EDDSA_25519_PRIVATE_BYTES) {
        return EXCP_BADARG_F(env, "Privkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PRIVATE_BYTES);
    }
    if (!enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_25519_PUBLIC_BYTES) {
        return EXCP_BADARG_F(env, "Pubkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PUBLIC_BYTES);
    }
    if (!enif_inspect_binary(env, argv[2], &message)) {
        return EXCP_BADARG(env, "Message must be a binary");
    }
    if (enif_compare(ATOM(no_context), argv[3]) == 0) {
        context.size = 0;
        context.data = (unsigned char *)(DECAF_ED25519_NO_CONTEXT);
    } else if (!enif_inspect_binary(env, argv[3], &context) || context.size > 255) {
        return EXCP_BADARG(env, "Context must be either the atom 'no_context' or a binary of size <= 255-bytes");
    }

    (void)decaf_ed25519_derive_keypair(keypair, privkey.data);
    (void)decaf_ed25519_keypair_extract_public_key(rederived_pubkey, keypair);
    if (decaf_memeq(rederived_pubkey, pubkey.data, sizeof(rederived_pubkey)) != DECAF_TRUE) {
        return EXCP_ERROR(env, "UNSAFE: Privkey and Pubkey are not part of the same keypair. See: https://github.com/MystenLabs/ed25519-unsafe-libs");
    }
    (void)decaf_ed25519_prehash_init(hash);
    (void)decaf_ed25519_prehash_update(hash, message.data, message.size);
    signature = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_25519_SIGNATURE_BYTES, &out));
    (void)decaf_ed25519_keypair_sign_prehash(signature, keypair, hash, context.data, context.size);
    (void)decaf_ed25519_prehash_destroy(hash);
    (void)decaf_ed25519_keypair_destroy(keypair);

    return out;
}

/* libdecaf_nif:ed25519_verify/5 */

static ERL_NIF_TERM
libdecaf_nif_ed25519_verify_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary signature;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    unsigned int prehashed;
    ErlNifBinary context;

    if (argc != 5) {
        return EXCP_BADARG(env, "argc must be 5");
    }

    if (!enif_inspect_binary(env, argv[0], &signature) || signature.size != DECAF_EDDSA_25519_SIGNATURE_BYTES) {
        return EXCP_BADARG_F(env, "Signature must be a binary of size %d-bytes", DECAF_EDDSA_25519_SIGNATURE_BYTES);
    }
    if (!enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_25519_PUBLIC_BYTES) {
        return EXCP_BADARG_F(env, "Pubkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PUBLIC_BYTES);
    }
    if (!enif_inspect_binary(env, argv[2], &message)) {
        return EXCP_BADARG(env, "Message must be a binary");
    }
    if (!enif_get_uint(env, argv[3], &prehashed) || (prehashed != 0 && prehashed != 1)) {
        return EXCP_BADARG(env, "Prehashed must be one of {0,1}");
    }
    if (enif_compare(ATOM(no_context), argv[4]) == 0) {
        context.size = 0;
        context.data = (unsigned char *)(DECAF_ED25519_NO_CONTEXT);
    } else if (!enif_inspect_binary(env, argv[4], &context) || context.size > 255) {
        return EXCP_BADARG(env, "Context must be either the atom 'no_context' or a binary of size <= 255-bytes");
    }

    if (decaf_ed25519_verify(signature.data, pubkey.data, message.data, message.size, prehashed, context.data, context.size) == DECAF_SUCCESS) {
        return ATOM(true);
    } else {
        return ATOM(false);
    }
}

/* libdecaf_nif:ed25519_verify_prehash/4 */

static ERL_NIF_TERM
libdecaf_nif_ed25519_verify_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary signature;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    ErlNifBinary context;
    decaf_ed25519_prehash_ctx_t hash;

    if (argc != 4) {
        return EXCP_BADARG(env, "argc must be 4");
    }

    if (!enif_inspect_binary(env, argv[0], &signature) || signature.size != DECAF_EDDSA_25519_SIGNATURE_BYTES) {
        return EXCP_BADARG_F(env, "Signature must be a binary of size %d-bytes", DECAF_EDDSA_25519_SIGNATURE_BYTES);
    }
    if (!enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_25519_PUBLIC_BYTES) {
        return EXCP_BADARG_F(env, "Pubkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PUBLIC_BYTES);
    }
    if (!enif_inspect_binary(env, argv[2], &message)) {
        return EXCP_BADARG(env, "Message must be a binary");
    }
    if (enif_compare(ATOM(no_context), argv[3]) == 0) {
        context.size = 0;
        context.data = (unsigned char *)(DECAF_ED25519_NO_CONTEXT);
    } else if (!enif_inspect_binary(env, argv[3], &context) || context.size > 255) {
        return EXCP_BADARG(env, "Context must be either the atom 'no_context' or a binary of size <= 255-bytes");
    }

    (void)decaf_ed25519_prehash_init(hash);
    (void)decaf_ed25519_prehash_update(hash, message.data, message.size);

    if (decaf_ed25519_verify_prehash(signature.data, pubkey.data, hash, context.data, context.size) == DECAF_SUCCESS) {
        (void)decaf_ed25519_prehash_destroy(hash);
        return ATOM(true);
    } else {
        (void)decaf_ed25519_prehash_destroy(hash);
        return ATOM(false);
    }
}

/* libdecaf_nif:ed25519_convert_public_key_to_x25519/1 */

static ERL_NIF_TERM
libdecaf_nif_ed25519_convert_public_key_to_x25519_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ed25519_pubkey;
    uint8_t *x25519_pubkey = NULL;
    ERL_NIF_TERM out_term;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }

    if (!enif_inspect_binary(env, argv[0], &ed25519_pubkey) || ed25519_pubkey.size != DECAF_EDDSA_25519_PUBLIC_BYTES) {
        return EXCP_BADARG_F(env, "Pubkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PUBLIC_BYTES);
    }

    x25519_pubkey = (uint8_t *)(enif_make_new_binary(env, DECAF_X25519_PUBLIC_BYTES, &out_term));

    (void)decaf_ed25519_convert_public_key_to_x25519(x25519_pubkey, ed25519_pubkey.data);

    return out_term;
}

/* libdecaf_nif:ed25519_convert_private_key_to_x25519/1 */

static ERL_NIF_TERM
libdecaf_nif_ed25519_convert_private_key_to_x25519_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ed25519_privkey;
    uint8_t *x25519_privkey = NULL;
    ERL_NIF_TERM out_term;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }

    if (!enif_inspect_binary(env, argv[0], &ed25519_privkey) || ed25519_privkey.size != DECAF_EDDSA_25519_PRIVATE_BYTES) {
        return EXCP_BADARG_F(env, "Privkey must be a binary of size %d-bytes", DECAF_EDDSA_25519_PRIVATE_BYTES);
    }

    x25519_privkey = (uint8_t *)(enif_make_new_binary(env, DECAF_X25519_PRIVATE_BYTES, &out_term));

    (void)decaf_ed25519_convert_private_key_to_x25519(x25519_privkey, ed25519_privkey.data);

    return out_term;
}
