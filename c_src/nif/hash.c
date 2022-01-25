// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "hash.h"

/* Trap Definitions */

typedef struct libdecaf_nif_hash_trap_s libdecaf_nif_hash_trap_t;
static void libdecaf_nif_hash_trap_dtor(ErlNifEnv *caller_env, void *obj);

struct libdecaf_nif_hash_trap_s {
    libdecaf_nif_trap_t super;
    libdecaf_nif_hash_t *hash;
    libdecaf_nif_hash_ctx_t *ctx;
    ErlNifBinary input_bin;
    size_t input_off;
    ErlNifBinary output_bin;
    size_t output_off;
    size_t output_len;
};

void
libdecaf_nif_hash_trap_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_hash_trap_t *trap = (void *)obj;
    if (trap != NULL && trap->ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_hash_trap_dtor:%s:%d\n", __FILE__, __LINE__);
        (void)trap->hash->destroy((void *)trap->ctx);
        (void)enif_free((void *)trap->ctx);
        trap->ctx = NULL;
        (void)enif_release_binary(&trap->output_bin);
    }
    return;
}

typedef struct libdecaf_nif_hash_update_trap_s libdecaf_nif_hash_update_trap_t;
static void libdecaf_nif_hash_update_trap_dtor(ErlNifEnv *caller_env, void *obj);

struct libdecaf_nif_hash_update_trap_s {
    libdecaf_nif_trap_t super;
    libdecaf_nif_hash_t *hash;
    libdecaf_nif_hash_ctx_t *new_ctx;
    ErlNifBinary input_bin;
    size_t input_off;
};

void
libdecaf_nif_hash_update_trap_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_hash_update_trap_t *trap = (void *)obj;
    if (trap != NULL && trap->new_ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_hash_update_trap_dtor:%s:%d\n", __FILE__, __LINE__);
        (void)trap->hash->destroy((void *)trap->new_ctx);
        (void)enif_release_resource((void *)trap->new_ctx);
        trap->new_ctx = NULL;
    }
    return;
}

/* Global Variables */

static libdecaf_nif_hash_table_t libdecaf_nif_hash_table_internal = {
    .sha2_512 =
        {
            .type = LIBDECAF_NIF_HASH_TYPE_SHA2_512,
            .max_output_len = 64,
            .init = (void *)decaf_sha512_init,
            .update = (void *)decaf_sha512_update,
            .final = (void *)decaf_sha512_final,
            .destroy = (void *)decaf_sha512_destroy,
        },
    .sha3_224 =
        {
            .type = LIBDECAF_NIF_HASH_TYPE_SHA3_224,
            .max_output_len = 28,
            .init = (void *)decaf_sha3_224_init,
            .update = (void *)decaf_sha3_224_update,
            .final = (void *)decaf_sha3_224_final,
            .destroy = (void *)decaf_sha3_224_destroy,
        },
    .sha3_256 =
        {
            .type = LIBDECAF_NIF_HASH_TYPE_SHA3_256,
            .max_output_len = 32,
            .init = (void *)decaf_sha3_256_init,
            .update = (void *)decaf_sha3_256_update,
            .final = (void *)decaf_sha3_256_final,
            .destroy = (void *)decaf_sha3_256_destroy,
        },
    .sha3_384 =
        {
            .type = LIBDECAF_NIF_HASH_TYPE_SHA3_384,
            .max_output_len = 48,
            .init = (void *)decaf_sha3_384_init,
            .update = (void *)decaf_sha3_384_update,
            .final = (void *)decaf_sha3_384_final,
            .destroy = (void *)decaf_sha3_384_destroy,
        },
    .sha3_512 =
        {
            .type = LIBDECAF_NIF_HASH_TYPE_SHA3_512,
            .max_output_len = 64,
            .init = (void *)decaf_sha3_512_init,
            .update = (void *)decaf_sha3_512_update,
            .final = (void *)decaf_sha3_512_final,
            .destroy = (void *)decaf_sha3_512_destroy,
        },
};

libdecaf_nif_hash_table_t *libdecaf_nif_hash_table = &libdecaf_nif_hash_table_internal;

/* Function Declarations */

static ERL_NIF_TERM libdecaf_nif_hash_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_hash_update_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

/* Function Definitions */

/* libdecaf_nif:sha2_512_hash/2 */
/* libdecaf_nif:sha3_224_hash/2 */
/* libdecaf_nif:sha3_256_hash/2 */
/* libdecaf_nif:sha3_384_hash/2 */
/* libdecaf_nif:sha3_512_hash/2 */

ERL_NIF_TERM
libdecaf_nif_hash_2(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM input_term;
    ErlNifBinary input_bin;
    unsigned long output_len;
    ErlNifBinary output_bin;
    libdecaf_nif_hash_ctx_t *ctx = NULL;
    ErlNifEnv *work_env = NULL;
    long nr_of_reductions;
    bool is_yielded = false;
    size_t slice_len;

    // Allocate work environment, we will use this if we need to yield.
    work_env = enif_alloc_env();
    if (work_env == NULL) {
        return EXCP_ERROR(env, "Can't allocate work_env = enif_alloc_env()");
    }

    if (argc != 2) {
        (void)enif_free_env(work_env);
        return EXCP_NOTSUP(env, "argc must be 2");
    }
    if (!enif_is_binary(env, argv[0]) && !enif_is_list(env, argv[0])) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }
    if (!enif_get_ulong(env, argv[1], &output_len) || output_len > hash->max_output_len) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'OutputLen'");
    }

    // Copy the input binary to the work environment so it will be kept when we are yielding.
    input_term = enif_make_copy(work_env, argv[0]);
    if (!enif_inspect_iolist_as_binary(work_env, input_term, &input_bin)) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }

    // Allocate out binary
    if (!enif_alloc_binary(output_len, &output_bin)) {
        (void)enif_free_env(work_env);
        return EXCP_ERROR(env, "Can't allocate 'Output' binary");
    }

    // Allocate hash context
    ctx = (void *)enif_alloc(sizeof(libdecaf_nif_hash_ctx_t));
    if (ctx == NULL) {
        (void)enif_release_binary(&output_bin);
        (void)enif_free_env(work_env);
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_hash_ctx_t");
    }

    ctx->type = hash->type;
    (void)hash->init((void *)ctx);

    nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();

    is_yielded = (nr_of_reductions < input_bin.size);
    slice_len = (is_yielded) ? nr_of_reductions : input_bin.size;
    (void)hash->update((void *)ctx, input_bin.data, slice_len);
    nr_of_reductions -= slice_len;

    if (is_yielded) {
        BUMP_ALL_REDS(env);
        libdecaf_nif_hash_trap_t *trap = (void *)enif_alloc_resource(libdecaf_nif_trap_resource_type, sizeof(*trap));
        if (trap == NULL) {
            (void)hash->destroy((void *)ctx);
            (void)enif_free((void *)ctx);
            (void)enif_release_binary(&output_bin);
            (void)enif_free_env(work_env);
            return EXCP_ERROR(env, "Can't allocate libdecaf_nif_hash_trap_t");
        }
        trap->super.type = LIBDECAF_NIF_TRAP_TYPE_HASH;
        trap->super.dtor = libdecaf_nif_hash_trap_dtor;
        trap->super.work_env = work_env;
        trap->hash = hash;
        trap->ctx = ctx;
        trap->input_bin = input_bin;
        trap->input_off = slice_len;
        trap->output_bin = output_bin;
        trap->output_off = 0;
        trap->output_len = output_len;
        ERL_NIF_TERM newargv[1];
        newargv[0] = enif_make_resource(env, (void *)trap);
        (void)enif_release_resource((void *)trap);
        return enif_schedule_nif(env, "libdecaf_nif_hash_2_continue", ERL_NIF_NORMAL_JOB_BOUND, libdecaf_nif_hash_2_continue, 1,
                                 newargv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        (void)hash->final((void *)ctx, output_bin.data, output_len);
        (void)hash->destroy((void *)ctx);
        (void)enif_free((void *)ctx);
        (void)enif_free_env(work_env);
        return enif_make_binary(env, &output_bin);
    }
}

ERL_NIF_TERM
libdecaf_nif_hash_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    long nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();
    bool is_yielded = false;
    size_t slice_len;
    libdecaf_nif_hash_trap_t *trap = NULL;

    if (argc != 1) {
        return EXCP_NOTSUP(env, "argc must be 1");
    }
    if (!enif_get_resource(env, argv[0], libdecaf_nif_trap_resource_type, (void **)&trap) ||
        trap->super.type != LIBDECAF_NIF_TRAP_TYPE_HASH || trap->ctx == NULL || trap->hash->type != trap->ctx->type) {
        return EXCP_BADARG(env, "Bad argument: 'Trap'");
    }
    is_yielded = (nr_of_reductions < (trap->input_bin.size - trap->input_off));
    slice_len = (is_yielded) ? nr_of_reductions : (trap->input_bin.size - trap->input_off);
    (void)trap->hash->update(trap->ctx, trap->input_bin.data + trap->input_off, slice_len);
    trap->input_off += slice_len;
    nr_of_reductions -= slice_len;
    if (is_yielded) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_hash_2_continue", ERL_NIF_NORMAL_JOB_BOUND, libdecaf_nif_hash_2_continue, argc,
                                 argv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        (void)trap->hash->final((void *)trap->ctx, trap->output_bin.data, trap->output_len);
        (void)trap->hash->destroy((void *)trap->ctx);
        (void)enif_free((void *)trap->ctx);
        trap->ctx = NULL;
        (void)enif_free_env(trap->super.work_env);
        trap->super.work_env = NULL;
        return enif_make_binary(env, &trap->output_bin);
    }
}

/* libdecaf_nif:sha2_512_hash_init/0 */
/* libdecaf_nif:sha3_224_hash_init/0 */
/* libdecaf_nif:sha3_256_hash_init/0 */
/* libdecaf_nif:sha3_384_hash_init/0 */
/* libdecaf_nif:sha3_512_hash_init/0 */

ERL_NIF_TERM
libdecaf_nif_hash_init_0(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_hash_ctx_t *ctx = NULL;
    ERL_NIF_TERM ctx_term;

    if (argc != 0) {
        return EXCP_NOTSUP(env, "argc must be 0");
    }

    ctx = (void *)enif_alloc_resource(libdecaf_nif_hash_resource_type, sizeof(libdecaf_nif_hash_ctx_t));
    if (ctx == NULL) {
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_hash_ctx_t");
    }
    ctx->type = hash->type;
    (void)hash->init((void *)ctx);

    ctx_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);

    return ctx_term;
}

/* libdecaf_nif:sha2_512_hash_update/2 */
/* libdecaf_nif:sha3_224_hash_update/2 */
/* libdecaf_nif:sha3_256_hash_update/2 */
/* libdecaf_nif:sha3_384_hash_update/2 */
/* libdecaf_nif:sha3_512_hash_update/2 */

ERL_NIF_TERM
libdecaf_nif_hash_update_2(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_hash_ctx_t *old_ctx = NULL;
    libdecaf_nif_hash_ctx_t *new_ctx = NULL;
    ERL_NIF_TERM input_term;
    ErlNifBinary input_bin;
    ErlNifEnv *work_env = NULL;
    long nr_of_reductions;
    bool is_yielded = false;
    size_t slice_len;
    ERL_NIF_TERM new_ctx_term;

    // Allocate work environment, we will use this if we need to yield.
    work_env = enif_alloc_env();
    if (work_env == NULL) {
        return EXCP_ERROR(env, "Can't allocate work_env = enif_alloc_env()");
    }

    if (argc != 2) {
        (void)enif_free_env(work_env);
        return EXCP_NOTSUP(env, "argc must be 2");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_hash_resource_type, (void **)&old_ctx) || hash->type != old_ctx->type) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'Ctx'");
    }
    if (!enif_is_binary(env, argv[1]) && !enif_is_list(env, argv[1])) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }

    // Copy the input binary to the work environment so it will be kept when we are yielding.
    input_term = enif_make_copy(work_env, argv[1]);
    if (!enif_inspect_iolist_as_binary(work_env, input_term, &input_bin)) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }

    // Allocate hash context
    new_ctx = (void *)enif_alloc_resource(libdecaf_nif_hash_resource_type, sizeof(libdecaf_nif_hash_ctx_t));
    if (new_ctx == NULL) {
        (void)enif_free_env(work_env);
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_hash_ctx_t");
    }
    (void)memcpy((void *)new_ctx, (void *)old_ctx, sizeof(libdecaf_nif_hash_ctx_t));

    nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();

    is_yielded = (nr_of_reductions < input_bin.size);
    slice_len = (is_yielded) ? nr_of_reductions : input_bin.size;
    (void)hash->update((void *)new_ctx, input_bin.data, slice_len);
    nr_of_reductions -= slice_len;

    if (is_yielded) {
        BUMP_ALL_REDS(env);
        libdecaf_nif_hash_update_trap_t *trap = (void *)enif_alloc_resource(libdecaf_nif_trap_resource_type, sizeof(*trap));
        if (trap == NULL) {
            (void)hash->destroy((void *)new_ctx);
            (void)enif_release_resource((void *)new_ctx);
            (void)enif_free_env(work_env);
            return EXCP_ERROR(env, "Can't allocate libdecaf_nif_hash_update_trap_t");
        }
        trap->super.type = LIBDECAF_NIF_TRAP_TYPE_HASH_UPDATE;
        trap->super.dtor = libdecaf_nif_hash_update_trap_dtor;
        trap->super.work_env = work_env;
        trap->hash = hash;
        trap->new_ctx = new_ctx;
        trap->input_bin = input_bin;
        trap->input_off = slice_len;
        ERL_NIF_TERM newargv[1];
        newargv[0] = enif_make_resource(env, (void *)trap);
        (void)enif_release_resource((void *)trap);
        return enif_schedule_nif(env, "libdecaf_nif_hash_update_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_hash_update_2_continue, 1, newargv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        new_ctx_term = enif_make_resource(env, (void *)new_ctx);
        (void)enif_release_resource((void *)new_ctx);
        (void)enif_free_env(work_env);
        return new_ctx_term;
    }
}

ERL_NIF_TERM
libdecaf_nif_hash_update_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    long nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();
    bool is_yielded = false;
    size_t slice_len;
    libdecaf_nif_hash_update_trap_t *trap = NULL;
    ERL_NIF_TERM new_ctx_term;

    if (argc != 1) {
        return EXCP_NOTSUP(env, "argc must be 1");
    }
    if (!enif_get_resource(env, argv[0], libdecaf_nif_trap_resource_type, (void **)&trap) ||
        trap->super.type != LIBDECAF_NIF_TRAP_TYPE_HASH_UPDATE || trap->new_ctx == NULL ||
        trap->hash->type != trap->new_ctx->type) {
        return EXCP_BADARG(env, "Bad argument: 'Trap'");
    }
    is_yielded = (nr_of_reductions < (trap->input_bin.size - trap->input_off));
    slice_len = (is_yielded) ? nr_of_reductions : (trap->input_bin.size - trap->input_off);
    (void)trap->hash->update(trap->new_ctx, trap->input_bin.data + trap->input_off, slice_len);
    trap->input_off += slice_len;
    nr_of_reductions -= slice_len;
    if (is_yielded) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_hash_update_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_hash_update_2_continue, argc, argv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        new_ctx_term = enif_make_resource(env, (void *)trap->new_ctx);
        (void)enif_release_resource((void *)trap->new_ctx);
        trap->new_ctx = NULL;
        (void)enif_free_env(trap->super.work_env);
        trap->super.work_env = NULL;
        return new_ctx_term;
    }
}

/* libdecaf_nif:sha2_512_hash_final/2 */
/* libdecaf_nif:sha3_224_hash_final/2 */
/* libdecaf_nif:sha3_256_hash_final/2 */
/* libdecaf_nif:sha3_384_hash_final/2 */
/* libdecaf_nif:sha3_512_hash_final/2 */

ERL_NIF_TERM
libdecaf_nif_hash_final_2(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_hash_ctx_t *old_ctx = NULL;
    libdecaf_nif_hash_ctx_t *new_ctx = NULL;
    unsigned long output_len;
    ErlNifBinary output_bin;

    if (argc != 2) {
        return EXCP_NOTSUP(env, "argc must be 2");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_hash_resource_type, (void **)&old_ctx) || hash->type != old_ctx->type) {
        return EXCP_BADARG(env, "Bad argument: 'Ctx'");
    }
    if (!enif_get_ulong(env, argv[1], &output_len) || output_len > hash->max_output_len) {
        return EXCP_BADARG(env, "Bad argument: 'OutputLen'");
    }

    // Allocate out binary
    if (!enif_alloc_binary(output_len, &output_bin)) {
        return EXCP_ERROR(env, "Can't allocate 'Output' binary");
    }

    // Allocate hash context
    new_ctx = (void *)enif_alloc(sizeof(libdecaf_nif_hash_ctx_t));
    if (new_ctx == NULL) {
        (void)enif_release_binary(&output_bin);
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_hash_ctx_t");
    }
    (void)memcpy((void *)new_ctx, (void *)old_ctx, sizeof(libdecaf_nif_hash_ctx_t));

    (void)hash->final((void *)new_ctx, output_bin.data, output_len);
    (void)hash->destroy((void *)new_ctx);
    (void)enif_free((void *)new_ctx);
    return enif_make_binary(env, &output_bin);
}
