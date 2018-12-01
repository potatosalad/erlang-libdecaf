// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include <decaf/spongerng.h>

/*
 * Erlang NIF functions
 */

/* libdecaf_nif:spongerng_init_from_buffer/2 */

static ERL_NIF_TERM
libdecaf_nif_spongerng_init_from_buffer_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    decaf_keccak_prng_s ctxbuf;
    decaf_keccak_prng_s *ctx = &ctxbuf;
    ErlNifBinary input;
    int deterministic = 0;
    ERL_NIF_TERM out_term;

    if (argc != 2 || !enif_inspect_iolist_as_binary(env, argv[0], &input) || !(argv[1] == ATOM_false || argv[1] == ATOM_true)) {
        return enif_make_badarg(env);
    }

    if (argv[1] == ATOM_true) {
        deterministic = 1;
    }

    (void)decaf_spongerng_init_from_buffer(ctx, input.data, input.size, deterministic);

    ctx = libdecaf_nif_alloc_spongerng_ctx(env);
    if (ctx == NULL) {
        return enif_make_badarg(env);
    }
    (void)memcpy(ctx, &ctxbuf, sizeof(decaf_keccak_prng_s));

    out_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);

    return out_term;
}

/* libdecaf_nif:spongerng_init_from_file/3 */

static ERL_NIF_TERM
libdecaf_nif_spongerng_init_from_file_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    decaf_keccak_prng_s ctxbuf;
    decaf_keccak_prng_s *ctx = &ctxbuf;
    ErlNifBinary input;
    char *filename = NULL;
    unsigned long inlen;
    int deterministic = 0;
    ERL_NIF_TERM out_term;

    if (argc != 3 || !enif_inspect_iolist_as_binary(env, argv[0], &input) || input.size == 0 ||
        !enif_get_ulong(env, argv[1], &inlen) || !(argv[2] == ATOM_false || argv[2] == ATOM_true)) {
        return enif_make_badarg(env);
    }

    filename = (void *)enif_alloc(input.size + 1);
    if (filename == NULL) {
        return enif_make_badarg(env);
    }
    (void)memcpy(filename, input.data, input.size);
    filename[input.size] = '\0';

    if (argv[2] == ATOM_true) {
        deterministic = 1;
    }

    if (decaf_spongerng_init_from_file(ctx, filename, inlen, deterministic) != DECAF_SUCCESS) {
        (void)enif_free((void *)filename);
        return enif_make_badarg(env);
    }
    (void)enif_free((void *)filename);

    ctx = libdecaf_nif_alloc_spongerng_ctx(env);
    if (ctx == NULL) {
        return enif_make_badarg(env);
    }
    (void)memcpy(ctx, &ctxbuf, sizeof(decaf_keccak_prng_s));

    out_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);

    return out_term;
}

/* libdecaf_nif:spongerng_init_from_dev_urandom/0 */

static ERL_NIF_TERM
libdecaf_nif_spongerng_init_from_dev_urandom_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    decaf_keccak_prng_s ctxbuf;
    decaf_keccak_prng_s *ctx = &ctxbuf;
    ERL_NIF_TERM out_term;

    if (argc != 0) {
        return enif_make_badarg(env);
    }

    if (decaf_spongerng_init_from_dev_urandom(ctx) != DECAF_SUCCESS) {
        return enif_make_badarg(env);
    }

    ctx = libdecaf_nif_alloc_spongerng_ctx(env);
    if (ctx == NULL) {
        return enif_make_badarg(env);
    }
    (void)memcpy(ctx, &ctxbuf, sizeof(decaf_keccak_prng_s));

    out_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);

    return out_term;
}

/* libdecaf_nif:spongerng_next/2 */

static ERL_NIF_TERM
libdecaf_nif_spongerng_next_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    decaf_keccak_prng_s *old_ctx = NULL;
    decaf_keccak_prng_s *new_ctx = NULL;
    unsigned long outlen;
    unsigned char *outbuf = NULL;
    ERL_NIF_TERM ctx_term;
    ERL_NIF_TERM out_term;

    if (argc != 2 || !libdecaf_nif_get_spongerng_ctx(env, argv[0], &old_ctx) || !enif_get_ulong(env, argv[1], &outlen)) {
        return enif_make_badarg(env);
    }

    new_ctx = libdecaf_nif_alloc_spongerng_ctx(env);
    if (new_ctx == NULL) {
        return enif_make_badarg(env);
    }
    (void)memcpy(new_ctx, old_ctx, sizeof(decaf_keccak_prng_s));

    outbuf = enif_make_new_binary(env, outlen, &out_term);
    (void)decaf_spongerng_next(new_ctx, outbuf, outlen);
    ctx_term = enif_make_resource(env, (void *)new_ctx);
    (void)enif_release_resource((void *)new_ctx);
    out_term = enif_make_tuple2(env, ctx_term, out_term);

    return out_term;
}

/* libdecaf_nif:spongerng_stir/2 */

static ERL_NIF_TERM
libdecaf_nif_spongerng_stir_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    decaf_keccak_prng_s *old_ctx = NULL;
    decaf_keccak_prng_s *new_ctx = NULL;
    ErlNifBinary input;
    ERL_NIF_TERM out_term;

    if (argc != 2 || !libdecaf_nif_get_spongerng_ctx(env, argv[0], &old_ctx) ||
        !enif_inspect_iolist_as_binary(env, argv[1], &input)) {
        return enif_make_badarg(env);
    }

    new_ctx = libdecaf_nif_alloc_spongerng_ctx(env);
    if (new_ctx == NULL) {
        return enif_make_badarg(env);
    }
    (void)memcpy(new_ctx, old_ctx, sizeof(decaf_keccak_prng_s));

    (void)decaf_spongerng_stir(new_ctx, input.data, input.size);
    out_term = enif_make_resource(env, (void *)new_ctx);
    (void)enif_release_resource((void *)new_ctx);

    return out_term;
}
