// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include <decaf/ed448.h>

/*
 * Erlang NIF functions
 */

/* libdecaf_nif:ed448_derive_public_key/1 */

static ERL_NIF_TERM
libdecaf_nif_ed448_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary privkey;

    if (argc != 1 || !enif_inspect_binary(env, argv[0], &privkey) || privkey.size != DECAF_EDDSA_448_PRIVATE_BYTES) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM out;
    uint8_t *pubkey = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_448_PUBLIC_BYTES, &out));

    (void)decaf_ed448_derive_public_key(pubkey, privkey.data);

    return out;
}

/* libdecaf_nif:ed448_sign/5 */

static ERL_NIF_TERM
libdecaf_nif_ed448_sign_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary privkey;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    unsigned int prehashed;
    ErlNifBinary context;

    if (argc != 5 || !enif_inspect_binary(env, argv[0], &privkey) || privkey.size != DECAF_EDDSA_448_PRIVATE_BYTES ||
        !enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_448_PUBLIC_BYTES ||
        !enif_inspect_binary(env, argv[2], &message) || !enif_get_uint(env, argv[3], &prehashed) ||
        (prehashed != 0 && prehashed != 1) || !enif_inspect_binary(env, argv[4], &context) || context.size > 255) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM out;
    uint8_t *signature = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_448_SIGNATURE_BYTES, &out));

    (void)decaf_ed448_sign(signature, privkey.data, pubkey.data, message.data, message.size, prehashed, context.data, context.size);

    return out;
}

/* libdecaf_nif:ed448_sign_prehash/4 */

static ERL_NIF_TERM
libdecaf_nif_ed448_sign_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary privkey;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    ErlNifBinary context;

    if (argc != 4 || !enif_inspect_binary(env, argv[0], &privkey) || privkey.size != DECAF_EDDSA_448_PRIVATE_BYTES ||
        !enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_448_PUBLIC_BYTES ||
        !enif_inspect_binary(env, argv[2], &message) || !enif_inspect_binary(env, argv[3], &context) || context.size > 255) {
        return enif_make_badarg(env);
    }

    decaf_ed448_prehash_ctx_t hash;
    (void)decaf_ed448_prehash_init(hash);
    (void)decaf_ed448_prehash_update(hash, message.data, message.size);

    ERL_NIF_TERM out;
    uint8_t *signature = (uint8_t *)(enif_make_new_binary(env, DECAF_EDDSA_448_SIGNATURE_BYTES, &out));

    (void)decaf_ed448_sign_prehash(signature, privkey.data, pubkey.data, hash, context.data, context.size);

    (void)decaf_ed448_prehash_destroy(hash);

    return out;
}

/* libdecaf_nif:ed448_verify/5 */

static ERL_NIF_TERM
libdecaf_nif_ed448_verify_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary signature;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    unsigned int prehashed;
    ErlNifBinary context;

    if (argc != 5 || !enif_inspect_binary(env, argv[0], &signature) || signature.size != DECAF_EDDSA_448_SIGNATURE_BYTES ||
        !enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_448_PUBLIC_BYTES ||
        !enif_inspect_binary(env, argv[2], &message) || !enif_get_uint(env, argv[3], &prehashed) ||
        (prehashed != 0 && prehashed != 1) || !enif_inspect_binary(env, argv[4], &context) || context.size > 255) {
        return enif_make_badarg(env);
    }

    if (decaf_ed448_verify(signature.data, pubkey.data, message.data, message.size, prehashed, context.data, context.size) ==
        DECAF_SUCCESS) {
        return libdecaf_nif_atom_table->ATOM_true;
    } else {
        return libdecaf_nif_atom_table->ATOM_false;
    }
}

/* libdecaf_nif:ed448_verify_prehash/4 */

static ERL_NIF_TERM
libdecaf_nif_ed448_verify_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary signature;
    ErlNifBinary pubkey;
    ErlNifBinary message;
    ErlNifBinary context;

    if (argc != 4 || !enif_inspect_binary(env, argv[0], &signature) || signature.size != DECAF_EDDSA_448_SIGNATURE_BYTES ||
        !enif_inspect_binary(env, argv[1], &pubkey) || pubkey.size != DECAF_EDDSA_448_PUBLIC_BYTES ||
        !enif_inspect_binary(env, argv[2], &message) || !enif_inspect_binary(env, argv[3], &context) || context.size > 255) {
        return enif_make_badarg(env);
    }

    decaf_ed448_prehash_ctx_t hash;
    (void)decaf_ed448_prehash_init(hash);
    (void)decaf_ed448_prehash_update(hash, message.data, message.size);

    if (decaf_ed448_verify_prehash(signature.data, pubkey.data, hash, context.data, context.size) == DECAF_SUCCESS) {
        (void)decaf_ed448_prehash_destroy(hash);
        return libdecaf_nif_atom_table->ATOM_true;
    } else {
        (void)decaf_ed448_prehash_destroy(hash);
        return libdecaf_nif_atom_table->ATOM_false;
    }
}

/* libdecaf_nif:ed448_convert_public_key_to_x448/1 */

static ERL_NIF_TERM
libdecaf_nif_ed448_convert_public_key_to_x448_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ed448_pubkey;
    uint8_t *x448_pubkey = NULL;
    ERL_NIF_TERM out_term;

    if (argc != 1 || !enif_inspect_binary(env, argv[0], &ed448_pubkey) || ed448_pubkey.size != DECAF_EDDSA_448_PUBLIC_BYTES) {
        return enif_make_badarg(env);
    }

    x448_pubkey = (uint8_t *)(enif_make_new_binary(env, DECAF_X448_PUBLIC_BYTES, &out_term));

    (void)decaf_ed448_convert_public_key_to_x448(x448_pubkey, ed448_pubkey.data);

    return out_term;
}

/* libdecaf_nif:ed448_convert_private_key_to_x448/1 */

static ERL_NIF_TERM
libdecaf_nif_ed448_convert_private_key_to_x448_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ed448_privkey;
    uint8_t *x448_privkey = NULL;
    ERL_NIF_TERM out_term;

    if (argc != 1 || !enif_inspect_binary(env, argv[0], &ed448_privkey) || ed448_privkey.size != DECAF_EDDSA_448_PRIVATE_BYTES) {
        return enif_make_badarg(env);
    }

    x448_privkey = (uint8_t *)(enif_make_new_binary(env, DECAF_X448_PRIVATE_BYTES, &out_term));

    (void)decaf_ed448_convert_private_key_to_x448(x448_privkey, ed448_privkey.data);

    return out_term;
}
