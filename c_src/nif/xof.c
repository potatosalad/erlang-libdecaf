// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "xof.h"

/* Trap Definitions */

typedef struct libdecaf_nif_xof_absorb_trap_s libdecaf_nif_xof_absorb_trap_t;
static void libdecaf_nif_xof_absorb_trap_dtor(ErlNifEnv *caller_env, void *obj);

struct libdecaf_nif_xof_absorb_trap_s {
    libdecaf_nif_trap_t super;
    libdecaf_nif_xof_t *xof;
    libdecaf_nif_xof_ctx_t *ctx;
    ErlNifBinary input_bin;
    size_t input_off;
    size_t output_len;
};

void
libdecaf_nif_xof_absorb_trap_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_xof_absorb_trap_t *trap = (void *)obj;
    if (trap != NULL && trap->ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_xof_absorb_trap_dtor:%s:%d\n", __FILE__, __LINE__);
        (void)trap->xof->destroy((void *)trap->ctx);
        (void)enif_free((void *)trap->ctx);
        trap->ctx = NULL;
    }
    return;
}

typedef struct libdecaf_nif_xof_squeeze_trap_s libdecaf_nif_xof_squeeze_trap_t;
static void libdecaf_nif_xof_squeeze_trap_dtor(ErlNifEnv *caller_env, void *obj);

struct libdecaf_nif_xof_squeeze_trap_s {
    libdecaf_nif_trap_t super;
    libdecaf_nif_xof_t *xof;
    libdecaf_nif_xof_ctx_t *ctx;
    ErlNifBinary output_bin;
    size_t output_off;
    size_t output_len;
};

void
libdecaf_nif_xof_squeeze_trap_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_xof_squeeze_trap_t *trap = (void *)obj;
    if (trap != NULL && trap->ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_xof_squeeze_trap_dtor:%s:%d\n", __FILE__, __LINE__);
        (void)trap->xof->destroy((void *)trap->ctx);
        (void)enif_free((void *)trap->ctx);
        trap->ctx = NULL;
        (void)enif_release_binary(&trap->output_bin);
    }
    return;
}

typedef struct libdecaf_nif_xof_update_trap_s libdecaf_nif_xof_update_trap_t;
static void libdecaf_nif_xof_update_trap_dtor(ErlNifEnv *caller_env, void *obj);

struct libdecaf_nif_xof_update_trap_s {
    libdecaf_nif_trap_t super;
    libdecaf_nif_xof_t *xof;
    libdecaf_nif_xof_ctx_t *new_ctx;
    ErlNifBinary input_bin;
    size_t input_off;
};

void
libdecaf_nif_xof_update_trap_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_xof_update_trap_t *trap = (void *)obj;
    if (trap != NULL && trap->new_ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_xof_update_trap_dtor:%s:%d\n", __FILE__, __LINE__);
        (void)trap->xof->destroy((void *)trap->new_ctx);
        (void)enif_release_resource((void *)trap->new_ctx);
        trap->new_ctx = NULL;
    }
    return;
}

typedef struct libdecaf_nif_xof_output_trap_s libdecaf_nif_xof_output_trap_t;
static void libdecaf_nif_xof_output_trap_dtor(ErlNifEnv *caller_env, void *obj);

struct libdecaf_nif_xof_output_trap_s {
    libdecaf_nif_trap_t super;
    libdecaf_nif_xof_t *xof;
    libdecaf_nif_xof_ctx_t *new_ctx;
    ErlNifBinary output_bin;
    size_t output_off;
    size_t output_len;
};

void
libdecaf_nif_xof_output_trap_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_xof_output_trap_t *trap = (void *)obj;
    if (trap != NULL && trap->new_ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_xof_output_trap_dtor:%s:%d\n", __FILE__, __LINE__);
        (void)trap->xof->destroy((void *)trap->new_ctx);
        (void)enif_release_resource((void *)trap->new_ctx);
        trap->new_ctx = NULL;
        (void)enif_release_binary(&trap->output_bin);
    }
    return;
}

/* Global Variables */

static libdecaf_nif_xof_table_t libdecaf_nif_xof_table_internal = {
    .shake128 =
        {
            .type = LIBDECAF_NIF_XOF_TYPE_SHAKE128,
            .init = (void *)decaf_shake128_init,
            .update = (void *)decaf_shake128_update,
            .output = (void *)decaf_shake128_output,
            .destroy = (void *)decaf_shake128_destroy,
        },
    .shake256 =
        {
            .type = LIBDECAF_NIF_XOF_TYPE_SHAKE256,
            .init = (void *)decaf_shake256_init,
            .update = (void *)decaf_shake256_update,
            .output = (void *)decaf_shake256_output,
            .destroy = (void *)decaf_shake256_destroy,
        },
};

libdecaf_nif_xof_table_t *libdecaf_nif_xof_table = &libdecaf_nif_xof_table_internal;

/* Function Declarations */

static ERL_NIF_TERM libdecaf_nif_xof_absorb_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_xof_squeeze_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_xof_update_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_xof_output_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

/* Function Definitions */

/* libdecaf_nif:shake128_xof/2 */
/* libdecaf_nif:shake256_xof/2 */

ERL_NIF_TERM
libdecaf_nif_xof_2(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM input_term;
    ErlNifBinary input_bin;
    unsigned long output_len;
    ErlNifBinary output_bin;
    libdecaf_nif_xof_ctx_t *ctx = NULL;
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
    if (!enif_get_ulong(env, argv[1], &output_len)) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'OutputLen'");
    }

    // Copy the input binary to the work environment so it will be kept when we are yielding.
    input_term = enif_make_copy(work_env, argv[0]);
    if (!enif_inspect_iolist_as_binary(work_env, input_term, &input_bin)) {
        (void)enif_free_env(work_env);
        return EXCP_BADARG(env, "Bad argument: 'Input'");
    }

    // Allocate xof context
    ctx = (void *)enif_alloc(sizeof(libdecaf_nif_xof_ctx_t));
    if (ctx == NULL) {
        (void)enif_release_binary(&output_bin);
        (void)enif_free_env(work_env);
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_ctx_t");
    }

    ctx->type = xof->type;
    ctx->squeezing = false;
    (void)xof->init((void *)ctx);

    nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();

    is_yielded = (nr_of_reductions < input_bin.size);
    slice_len = (is_yielded) ? nr_of_reductions : input_bin.size;
    (void)xof->update((void *)ctx, input_bin.data, slice_len);
    nr_of_reductions -= slice_len;

    if (is_yielded) {
        BUMP_ALL_REDS(env);
        libdecaf_nif_xof_absorb_trap_t *trap = (void *)enif_alloc_resource(libdecaf_nif_trap_resource_type, sizeof(*trap));
        if (trap == NULL) {
            (void)xof->destroy((void *)ctx);
            (void)enif_free((void *)ctx);
            (void)enif_release_binary(&output_bin);
            (void)enif_free_env(work_env);
            return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_absorb_trap_t");
        }
        trap->super.type = LIBDECAF_NIF_TRAP_TYPE_XOF_ABSORB;
        trap->super.dtor = libdecaf_nif_xof_absorb_trap_dtor;
        trap->super.work_env = work_env;
        trap->xof = xof;
        trap->ctx = ctx;
        trap->input_bin = input_bin;
        trap->input_off = slice_len;
        trap->output_len = output_len;
        ERL_NIF_TERM newargv[1];
        newargv[0] = enif_make_resource(env, (void *)trap);
        (void)enif_release_resource((void *)trap);
        return enif_schedule_nif(env, "libdecaf_nif_xof_absorb_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_xof_absorb_2_continue, 1, newargv);
    } else {
        // Allocate out binary
        if (!enif_alloc_binary(output_len, &output_bin)) {
            (void)xof->destroy((void *)ctx);
            (void)enif_free((void *)ctx);
            (void)enif_free_env(work_env);
            return EXCP_ERROR(env, "Can't allocate 'Output' binary");
        }

        is_yielded = (nr_of_reductions < output_len);
        slice_len = (is_yielded) ? nr_of_reductions : output_len;
        ctx->squeezing = true;
        (void)xof->output((void *)ctx, output_bin.data, slice_len);
        nr_of_reductions -= slice_len;

        if (is_yielded) {
            BUMP_ALL_REDS(env);
            libdecaf_nif_xof_squeeze_trap_t *trap = (void *)enif_alloc_resource(libdecaf_nif_trap_resource_type, sizeof(*trap));
            if (trap == NULL) {
                (void)xof->destroy((void *)ctx);
                (void)enif_free((void *)ctx);
                (void)enif_release_binary(&output_bin);
                (void)enif_free_env(work_env);
                return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_squeeze_trap_t");
            }
            trap->super.type = LIBDECAF_NIF_TRAP_TYPE_XOF_SQUEEZE;
            trap->super.dtor = libdecaf_nif_xof_squeeze_trap_dtor;
            trap->super.work_env = NULL;
            trap->xof = xof;
            trap->ctx = ctx;
            trap->output_bin = output_bin;
            trap->output_off = slice_len;
            trap->output_len = output_len;
            ERL_NIF_TERM newargv[1];
            newargv[0] = enif_make_resource(env, (void *)trap);
            (void)enif_release_resource((void *)trap);
            (void)enif_free_env(work_env);
            return enif_schedule_nif(env, "libdecaf_nif_xof_squeeze_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                     libdecaf_nif_xof_squeeze_2_continue, 1, newargv);
        } else {
            BUMP_REMAINING_REDS(env, nr_of_reductions);
            (void)xof->destroy((void *)ctx);
            (void)enif_free((void *)ctx);
            (void)enif_free_env(work_env);
            return enif_make_binary(env, &output_bin);
        }
    }
}

ERL_NIF_TERM
libdecaf_nif_xof_absorb_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    long nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();
    bool is_yielded = false;
    size_t slice_len;
    libdecaf_nif_xof_absorb_trap_t *old_trap = NULL;
    ErlNifBinary output_bin;

    if (argc != 1) {
        return EXCP_NOTSUP(env, "argc must be 1");
    }
    if (!enif_get_resource(env, argv[0], libdecaf_nif_trap_resource_type, (void **)&old_trap) ||
        old_trap->super.type != LIBDECAF_NIF_TRAP_TYPE_XOF_ABSORB || old_trap->ctx == NULL ||
        old_trap->xof->type != old_trap->ctx->type || old_trap->ctx->squeezing != false) {
        return EXCP_BADARG(env, "Bad argument: 'Trap'");
    }
    is_yielded = (nr_of_reductions < (old_trap->input_bin.size - old_trap->input_off));
    slice_len = (is_yielded) ? nr_of_reductions : (old_trap->input_bin.size - old_trap->input_off);
    (void)old_trap->xof->update(old_trap->ctx, old_trap->input_bin.data + old_trap->input_off, slice_len);
    old_trap->input_off += slice_len;
    nr_of_reductions -= slice_len;
    if (is_yielded) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_xof_absorb_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_xof_absorb_2_continue, argc, argv);
    } else {
        // Allocate out binary
        if (!enif_alloc_binary(old_trap->output_len, &output_bin)) {
            return EXCP_ERROR(env, "Can't allocate 'Output' binary");
        }

        is_yielded = (nr_of_reductions < old_trap->output_len);
        slice_len = (is_yielded) ? nr_of_reductions : old_trap->output_len;
        old_trap->ctx->squeezing = true;
        (void)old_trap->xof->output((void *)old_trap->ctx, output_bin.data, slice_len);
        nr_of_reductions -= slice_len;

        if (is_yielded) {
            BUMP_ALL_REDS(env);
            libdecaf_nif_xof_squeeze_trap_t *new_trap =
                (void *)enif_alloc_resource(libdecaf_nif_trap_resource_type, sizeof(*new_trap));
            if (new_trap == NULL) {
                return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_squeeze_trap_t");
            }
            new_trap->super.type = LIBDECAF_NIF_TRAP_TYPE_XOF_SQUEEZE;
            new_trap->super.dtor = libdecaf_nif_xof_squeeze_trap_dtor;
            new_trap->super.work_env = NULL;
            new_trap->xof = old_trap->xof;
            new_trap->ctx = old_trap->ctx;
            new_trap->output_bin = output_bin;
            new_trap->output_off = slice_len;
            new_trap->output_len = old_trap->output_len;
            ERL_NIF_TERM newargv[1];
            newargv[0] = enif_make_resource(env, (void *)new_trap);
            (void)enif_release_resource((void *)new_trap);
            old_trap->ctx = NULL;
            (void)enif_free_env(old_trap->super.work_env);
            old_trap->super.work_env = NULL;
            return enif_schedule_nif(env, "libdecaf_nif_xof_squeeze_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                     libdecaf_nif_xof_squeeze_2_continue, 1, newargv);
        } else {
            BUMP_REMAINING_REDS(env, nr_of_reductions);
            (void)old_trap->xof->destroy((void *)old_trap->ctx);
            (void)enif_free((void *)old_trap->ctx);
            old_trap->ctx = NULL;
            (void)enif_free_env(old_trap->super.work_env);
            old_trap->super.work_env = NULL;
            return enif_make_binary(env, &output_bin);
        }
    }
}

ERL_NIF_TERM
libdecaf_nif_xof_squeeze_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    long nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();
    bool is_yielded = false;
    size_t slice_len;
    libdecaf_nif_xof_squeeze_trap_t *trap = NULL;

    if (argc != 1) {
        return EXCP_NOTSUP(env, "argc must be 1");
    }
    if (!enif_get_resource(env, argv[0], libdecaf_nif_trap_resource_type, (void **)&trap) ||
        trap->super.type != LIBDECAF_NIF_TRAP_TYPE_XOF_SQUEEZE || trap->ctx == NULL || trap->xof->type != trap->ctx->type ||
        trap->ctx->squeezing != true) {
        return EXCP_BADARG(env, "Bad argument: 'Trap'");
    }
    is_yielded = (nr_of_reductions < (trap->output_len - trap->output_off));
    slice_len = (is_yielded) ? nr_of_reductions : (trap->output_len - trap->output_off);
    (void)trap->xof->output(trap->ctx, trap->output_bin.data + trap->output_off, slice_len);
    trap->output_off += slice_len;
    nr_of_reductions -= slice_len;
    if (is_yielded) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_xof_squeeze_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_xof_squeeze_2_continue, argc, argv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        (void)trap->xof->destroy((void *)trap->ctx);
        (void)enif_free((void *)trap->ctx);
        trap->ctx = NULL;
        return enif_make_binary(env, &trap->output_bin);
    }
}

/* libdecaf_nif:shake128_xof_init/0 */
/* libdecaf_nif:shake256_xof_init/0 */

ERL_NIF_TERM
libdecaf_nif_xof_init_0(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_xof_ctx_t *ctx = NULL;
    ERL_NIF_TERM ctx_term;

    if (argc != 0) {
        return EXCP_NOTSUP(env, "argc must be 0");
    }

    ctx = (void *)enif_alloc_resource(libdecaf_nif_xof_resource_type, sizeof(libdecaf_nif_xof_ctx_t));
    if (ctx == NULL) {
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_ctx_t");
    }
    ctx->type = xof->type;
    ctx->squeezing = false;
    (void)xof->init((void *)ctx);

    ctx_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);

    return ctx_term;
}

/* libdecaf_nif:shake128_xof_update/2 */
/* libdecaf_nif:shake256_xof_update/2 */

ERL_NIF_TERM
libdecaf_nif_xof_update_2(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_xof_ctx_t *old_ctx = NULL;
    libdecaf_nif_xof_ctx_t *new_ctx = NULL;
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

    if (!enif_get_resource(env, argv[0], libdecaf_nif_xof_resource_type, (void **)&old_ctx) || xof->type != old_ctx->type ||
        old_ctx->squeezing != false) {
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

    // Allocate xof context
    new_ctx = (void *)enif_alloc_resource(libdecaf_nif_xof_resource_type, sizeof(libdecaf_nif_xof_ctx_t));
    if (new_ctx == NULL) {
        (void)enif_free_env(work_env);
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_ctx_t");
    }
    (void)memcpy((void *)new_ctx, (void *)old_ctx, sizeof(libdecaf_nif_xof_ctx_t));

    nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();

    is_yielded = (nr_of_reductions < input_bin.size);
    slice_len = (is_yielded) ? nr_of_reductions : input_bin.size;
    (void)xof->update((void *)new_ctx, input_bin.data, slice_len);
    nr_of_reductions -= slice_len;

    if (is_yielded) {
        BUMP_ALL_REDS(env);
        libdecaf_nif_xof_update_trap_t *trap = (void *)enif_alloc_resource(libdecaf_nif_trap_resource_type, sizeof(*trap));
        if (trap == NULL) {
            (void)xof->destroy((void *)new_ctx);
            (void)enif_release_resource((void *)new_ctx);
            (void)enif_free_env(work_env);
            return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_update_trap_t");
        }
        trap->super.type = LIBDECAF_NIF_TRAP_TYPE_XOF_UPDATE;
        trap->super.dtor = libdecaf_nif_xof_update_trap_dtor;
        trap->super.work_env = work_env;
        trap->xof = xof;
        trap->new_ctx = new_ctx;
        trap->input_bin = input_bin;
        trap->input_off = slice_len;
        ERL_NIF_TERM newargv[1];
        newargv[0] = enif_make_resource(env, (void *)trap);
        (void)enif_release_resource((void *)trap);
        return enif_schedule_nif(env, "libdecaf_nif_xof_update_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_xof_update_2_continue, 1, newargv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        new_ctx_term = enif_make_resource(env, (void *)new_ctx);
        (void)enif_release_resource((void *)new_ctx);
        (void)enif_free_env(work_env);
        return new_ctx_term;
    }
}

ERL_NIF_TERM
libdecaf_nif_xof_update_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    long nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();
    bool is_yielded = false;
    size_t slice_len;
    libdecaf_nif_xof_update_trap_t *trap = NULL;
    ERL_NIF_TERM new_ctx_term;

    if (argc != 1) {
        return EXCP_NOTSUP(env, "argc must be 1");
    }
    if (!enif_get_resource(env, argv[0], libdecaf_nif_trap_resource_type, (void **)&trap) ||
        trap->super.type != LIBDECAF_NIF_TRAP_TYPE_XOF_UPDATE || trap->new_ctx == NULL || trap->xof->type != trap->new_ctx->type ||
        trap->new_ctx->squeezing != false) {
        return EXCP_BADARG(env, "Bad argument: 'Trap'");
    }
    is_yielded = (nr_of_reductions < (trap->input_bin.size - trap->input_off));
    slice_len = (is_yielded) ? nr_of_reductions : (trap->input_bin.size - trap->input_off);
    (void)trap->xof->update(trap->new_ctx, trap->input_bin.data + trap->input_off, slice_len);
    trap->input_off += slice_len;
    nr_of_reductions -= slice_len;
    if (is_yielded) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_xof_update_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_xof_update_2_continue, argc, argv);
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

/* libdecaf_nif:shake128_xof_output/2 */
/* libdecaf_nif:shake256_xof_output/2 */

ERL_NIF_TERM
libdecaf_nif_xof_output_2(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_xof_ctx_t *old_ctx = NULL;
    libdecaf_nif_xof_ctx_t *new_ctx = NULL;
    unsigned long output_len;
    ErlNifBinary output_bin;
    long nr_of_reductions;
    bool is_yielded = false;
    size_t slice_len;
    ERL_NIF_TERM new_ctx_term;

    if (argc != 2) {
        return EXCP_NOTSUP(env, "argc must be 2");
    }

    if (!enif_get_resource(env, argv[0], libdecaf_nif_xof_resource_type, (void **)&old_ctx) || xof->type != old_ctx->type) {
        return EXCP_BADARG(env, "Bad argument: 'Ctx'");
    }
    if (!enif_get_ulong(env, argv[1], &output_len)) {
        return EXCP_BADARG(env, "Bad argument: 'OutputLen'");
    }

    // Allocate out binary
    if (!enif_alloc_binary(output_len, &output_bin)) {
        return EXCP_ERROR(env, "Can't allocate 'Output' binary");
    }

    // Allocate xof context
    new_ctx = (void *)enif_alloc_resource(libdecaf_nif_xof_resource_type, sizeof(libdecaf_nif_xof_ctx_t));
    if (new_ctx == NULL) {
        (void)enif_release_binary(&output_bin);
        return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_ctx_t");
    }
    (void)memcpy((void *)new_ctx, (void *)old_ctx, sizeof(libdecaf_nif_xof_ctx_t));

    nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();

    is_yielded = (nr_of_reductions < output_len);
    slice_len = (is_yielded) ? nr_of_reductions : output_len;
    new_ctx->squeezing = true;
    (void)xof->output((void *)new_ctx, output_bin.data, slice_len);
    nr_of_reductions -= slice_len;

    if (is_yielded) {
        BUMP_ALL_REDS(env);
        libdecaf_nif_xof_output_trap_t *trap = (void *)enif_alloc_resource(libdecaf_nif_trap_resource_type, sizeof(*trap));
        if (trap == NULL) {
            (void)xof->destroy((void *)new_ctx);
            (void)enif_release_resource((void *)new_ctx);
            (void)enif_release_binary(&output_bin);
            return EXCP_ERROR(env, "Can't allocate libdecaf_nif_xof_output_trap_t");
        }
        trap->super.type = LIBDECAF_NIF_TRAP_TYPE_XOF_OUTPUT;
        trap->super.dtor = libdecaf_nif_xof_output_trap_dtor;
        trap->super.work_env = NULL;
        trap->xof = xof;
        trap->new_ctx = new_ctx;
        trap->output_bin = output_bin;
        trap->output_off = slice_len;
        trap->output_len = output_len;
        ERL_NIF_TERM newargv[1];
        newargv[0] = enif_make_resource(env, (void *)trap);
        (void)enif_release_resource((void *)trap);
        return enif_schedule_nif(env, "libdecaf_nif_xof_output_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_xof_output_2_continue, 1, newargv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        new_ctx_term = enif_make_resource(env, (void *)new_ctx);
        (void)enif_release_resource((void *)new_ctx);
        return enif_make_tuple2(env, new_ctx_term, enif_make_binary(env, &output_bin));
    }
}

ERL_NIF_TERM
libdecaf_nif_xof_output_2_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    long nr_of_reductions = REDUCTIONS_UNTIL_YCF_YIELD();
    bool is_yielded = false;
    size_t slice_len;
    libdecaf_nif_xof_output_trap_t *trap = NULL;
    ERL_NIF_TERM new_ctx_term;

    if (argc != 1) {
        return EXCP_NOTSUP(env, "argc must be 1");
    }
    if (!enif_get_resource(env, argv[0], libdecaf_nif_trap_resource_type, (void **)&trap) ||
        trap->super.type != LIBDECAF_NIF_TRAP_TYPE_XOF_OUTPUT || trap->new_ctx == NULL || trap->xof->type != trap->new_ctx->type ||
        trap->new_ctx->squeezing != true) {
        return EXCP_BADARG(env, "Bad argument: 'Trap'");
    }
    is_yielded = (nr_of_reductions < (trap->output_len - trap->output_off));
    slice_len = (is_yielded) ? nr_of_reductions : (trap->output_len - trap->output_off);
    (void)trap->xof->output(trap->new_ctx, trap->output_bin.data + trap->output_off, slice_len);
    trap->output_off += slice_len;
    nr_of_reductions -= slice_len;
    if (is_yielded) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_xof_output_2_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_xof_output_2_continue, argc, argv);
    } else {
        BUMP_REMAINING_REDS(env, nr_of_reductions);
        new_ctx_term = enif_make_resource(env, (void *)trap->new_ctx);
        (void)enif_release_resource((void *)trap->new_ctx);
        trap->new_ctx = NULL;
        return enif_make_tuple2(env, new_ctx_term, enif_make_binary(env, &trap->output_bin));
    }
}
