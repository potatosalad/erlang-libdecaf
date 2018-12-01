// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include <decaf/point_255.h>

/*
 * Erlang NIF functions
 */

/* libdecaf_nif:x25519_derive_public_key/1 */

static ERL_NIF_TERM
libdecaf_nif_x25519_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary scalar;

    if (argc != 1 || !enif_inspect_binary(env, argv[0], &scalar) || scalar.size != DECAF_X25519_PRIVATE_BYTES) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM out;
    uint8_t *u = (uint8_t *)(enif_make_new_binary(env, DECAF_X25519_PUBLIC_BYTES, &out));

    (void)decaf_x25519_derive_public_key(u, scalar.data);

    return out;
}

/* libdecaf_nif:x25519/2 */

static ERL_NIF_TERM
libdecaf_nif_x25519_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary base;
    ErlNifBinary scalar;

    if (argc != 2 || !enif_inspect_binary(env, argv[0], &base) || base.size != DECAF_X25519_PUBLIC_BYTES ||
        !enif_inspect_binary(env, argv[1], &scalar) || scalar.size != DECAF_X25519_PRIVATE_BYTES) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM out;
    uint8_t *u = (uint8_t *)(enif_make_new_binary(env, DECAF_X25519_PUBLIC_BYTES, &out));

    if (decaf_x25519(u, base.data, scalar.data) == DECAF_SUCCESS) {
        return out;
    } else {
        return ATOM_error;
    }
}
