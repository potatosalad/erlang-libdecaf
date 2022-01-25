// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "csprng.h"

/* Function Definitions */

/* libdecaf_nif:spongerng_csprng_init_from_buffer/2 */

ERL_NIF_TERM
libdecaf_nif_spongerng_csprng_init_from_buffer_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_csprng_ctx_t *ctx = NULL;
    ErlNifBinary input_bin;
    int deterministic = 0;
    ERL_NIF_TERM ctx_term;

    if (argc != 2) {
        return EXCP_NOTSUP(env, "argc must be 2");
    }
    if (!enif_inspect_iolist_as_binary(env, argv[0], &input_bin)) {
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }
    if (!(argv[1] == libdecaf_nif_atom_table->ATOM_false || argv[1] == libdecaf_nif_atom_table->ATOM_true)) {
        return EXCP_BADARG(env, "Bad argument: 'Deterministic'");
    }

    if (argv[1] == libdecaf_nif_atom_table->ATOM_true) {
        deterministic = 1;
    }

    ctx = (void *)enif_alloc_resource(libdecaf_nif_csprng_resource_type, sizeof(libdecaf_nif_csprng_ctx_t));
    if (ctx == NULL) {
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_csprng_ctx_t");
    }

    (void)decaf_spongerng_init_from_buffer((void *)ctx, input_bin.data, input_bin.size, deterministic);

    ctx_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);

    return ctx_term;
}

/* libdecaf_nif:spongerng_csprng_init_from_file/3 */

ERL_NIF_TERM
libdecaf_nif_spongerng_csprng_init_from_file_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_csprng_ctx_t *ctx = NULL;
    ErlNifBinary input_bin;
    char *filename = NULL;
    unsigned long input_len;
    int deterministic = 0;
    ERL_NIF_TERM ctx_term;

    if (argc != 3) {
        return EXCP_NOTSUP(env, "argc must be 3");
    }
    if (!enif_inspect_iolist_as_binary(env, argv[0], &input_bin) || input_bin.size == 0) {
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }
    if (!enif_get_ulong(env, argv[1], &input_len)) {
        return EXCP_BADARG(env, "Bad argument: 'InputLen'");
    }
    if (!(argv[2] == libdecaf_nif_atom_table->ATOM_false || argv[2] == libdecaf_nif_atom_table->ATOM_true)) {
        return EXCP_BADARG(env, "Bad argument: 'Deterministic'");
    }

    if (argv[2] == libdecaf_nif_atom_table->ATOM_true) {
        deterministic = 1;
    }

    ctx = (void *)enif_alloc_resource(libdecaf_nif_csprng_resource_type, sizeof(libdecaf_nif_csprng_ctx_t));
    if (ctx == NULL) {
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_csprng_ctx_t");
    }

    filename = (void *)enif_alloc(input_bin.size + 1);
    if (filename == NULL) {
        (void)enif_release_resource((void *)ctx);
        return EXCP_ERROR(env, "Can't allocate filename");
    }
    (void)memcpy(filename, input_bin.data, input_bin.size);
    filename[input_bin.size] = '\0';

    if (decaf_spongerng_init_from_file((void *)ctx, filename, input_len, deterministic) != DECAF_SUCCESS) {
        (void)enif_free((void *)filename);
        (void)enif_release_resource((void *)ctx);
        return EXCP_ERROR(env, "Failure to initialize from file");
    }

    ctx_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);
    (void)enif_free((void *)filename);

    return ctx_term;
}

/* libdecaf_nif:spongerng_csprng_init_from_dev_urandom/0 */

ERL_NIF_TERM
libdecaf_nif_spongerng_csprng_init_from_dev_urandom_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_csprng_ctx_t *ctx = NULL;
    ERL_NIF_TERM ctx_term;

    if (argc != 0) {
        return EXCP_NOTSUP(env, "argc must be 0");
    }

    ctx = (void *)enif_alloc_resource(libdecaf_nif_csprng_resource_type, sizeof(libdecaf_nif_csprng_ctx_t));
    if (ctx == NULL) {
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_csprng_ctx_t");
    }

    if (decaf_spongerng_init_from_dev_urandom((void *)ctx) != DECAF_SUCCESS) {
        (void)enif_release_resource((void *)ctx);
        return EXCP_ERROR(env, "Failure to initialize from /dev/urandom");
    }

    ctx_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);

    return ctx_term;
}

/* libdecaf_nif:spongerng_csprng_next/2 */

ERL_NIF_TERM
libdecaf_nif_spongerng_csprng_next_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_csprng_ctx_t *old_ctx = NULL;
    libdecaf_nif_csprng_ctx_t *new_ctx = NULL;
    unsigned long output_len;
    ErlNifBinary output_bin;
    ERL_NIF_TERM new_ctx_term;

    if (argc != 2) {
        return EXCP_NOTSUP(env, "argc must be 2");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_csprng_resource_type, (void **)&old_ctx)) {
        return EXCP_BADARG(env, "Bad argument: 'Ctx'");
    }
    if (!enif_get_ulong(env, argv[1], &output_len)) {
        return EXCP_BADARG(env, "Bad argument: 'OutputLen'");
    }

    // Allocate out binary
    if (!enif_alloc_binary(output_len, &output_bin)) {
        return EXCP_ERROR(env, "Can't allocate 'Output' binary");
    }

    // Allocate csprng context
    new_ctx = (void *)enif_alloc_resource(libdecaf_nif_csprng_resource_type, sizeof(libdecaf_nif_csprng_ctx_t));
    if (new_ctx == NULL) {
        (void)enif_release_binary(&output_bin);
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_csprng_ctx_t");
    }
    (void)memcpy((void *)new_ctx, (void *)old_ctx, sizeof(libdecaf_nif_csprng_ctx_t));

    (void)decaf_spongerng_next((void *)new_ctx, output_bin.data, output_len);

    new_ctx_term = enif_make_resource(env, (void *)new_ctx);
    (void)enif_release_resource((void *)new_ctx);
    return enif_make_tuple2(env, new_ctx_term, enif_make_binary(env, &output_bin));
}

/* libdecaf_nif:spongerng_csprng_stir/2 */

ERL_NIF_TERM
libdecaf_nif_spongerng_csprng_stir_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_csprng_ctx_t *old_ctx = NULL;
    libdecaf_nif_csprng_ctx_t *new_ctx = NULL;
    ErlNifBinary input_bin;
    ERL_NIF_TERM new_ctx_term;

    if (argc != 2) {
        return EXCP_NOTSUP(env, "argc must be 2");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_csprng_resource_type, (void **)&old_ctx)) {
        return EXCP_BADARG(env, "Bad argument: 'Ctx'");
    }
    if (!enif_inspect_iolist_as_binary(env, argv[1], &input_bin)) {
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }

    // Allocate csprng context
    new_ctx = (void *)enif_alloc_resource(libdecaf_nif_csprng_resource_type, sizeof(libdecaf_nif_csprng_ctx_t));
    if (new_ctx == NULL) {
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_csprng_ctx_t");
    }
    (void)memcpy((void *)new_ctx, (void *)old_ctx, sizeof(libdecaf_nif_csprng_ctx_t));

    (void)decaf_spongerng_stir((void *)new_ctx, input_bin.data, input_bin.size);

    new_ctx_term = enif_make_resource(env, (void *)new_ctx);
    (void)enif_release_resource((void *)new_ctx);
    return new_ctx_term;
}
