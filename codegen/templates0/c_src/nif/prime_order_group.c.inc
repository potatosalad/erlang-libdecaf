{% macro implementation(group) %}
{% set api = group.upstream %}
{% set p = 'libdecaf_nif_' + group.name %}
#include "{{ group.name }}.h"
#include <decaf/point_{{ group.bits }}.h>

/* Points and scalars cross the
 * NIF boundary only in canonical wire format. Stack points retain the
 * alignment required by upstream; precomputed tables are aligned separately.
 * ATOM(badarg) is a sentinel: raise the exception after wiping temporaries. */

typedef struct {
    void *allocation;
    {{ api }}_precomputed_s * table;
} {{ p }}_precomputed_t;

static ErlNifResourceType *{{ p }}_precomputed_type = NULL;

static void
{{ p }}_precomputed_dtor(ErlNifEnv *env, void *obj)
{
    {{ p }}_precomputed_t *ctx = obj;
    (void)env;
    if (ctx->table != NULL) {
        {{ api }}_precomputed_destroy(ctx->table);
    }
    if (ctx->allocation != NULL)
        enif_free(ctx->allocation);
}

int
{{ p }}_load(ErlNifEnv *env)
{
    {{ p }}_precomputed_type = enif_open_resource_type(
        env, "libdecaf_nif", "{{ group.name }}_precomputed", {{ p }}_precomputed_dtor,
        ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    return {{ p }}_precomputed_type != NULL ? 0 : -1;
}

static int
{{ p }}_get_point(ErlNifEnv *env, ERL_NIF_TERM term, {{ api }}_point_t point)
{
    ErlNifBinary bin;
    return enif_inspect_binary(env, term, &bin) && bin.size == {{ group.point_bytes }} &&
           {{ api }}_point_decode(point, bin.data, DECAF_TRUE) == DECAF_SUCCESS;
}

static int
{{ p }}_get_scalar(ErlNifEnv *env, ERL_NIF_TERM term, {{ api }}_scalar_t scalar)
{
    ErlNifBinary bin;
    return enif_inspect_binary(env, term, &bin) && bin.size == {{ group.scalar_bytes }} &&
           {{ api }}_scalar_decode(scalar, bin.data) == DECAF_SUCCESS;
}

static ERL_NIF_TERM
{{ p }}_make_point(ErlNifEnv *env, const {{ api }}_point_t point)
{
    ERL_NIF_TERM out;
    unsigned char *bytes = enif_make_new_binary(env, {{ group.point_bytes }}, &out);
    if (bytes == NULL)
        return EXCP_ERROR(env, "Cannot allocate point binary");
    {{ api }}_point_encode(bytes, point);
    return out;
}

static ERL_NIF_TERM
{{ p }}_make_scalar(ErlNifEnv *env, const {{ api }}_scalar_t scalar)
{
    ERL_NIF_TERM out;
    unsigned char *bytes = enif_make_new_binary(env, {{ group.scalar_bytes }}, &out);
    if (bytes == NULL)
        return EXCP_ERROR(env, "Cannot allocate scalar binary");
    {{ api }}_scalar_encode(bytes, scalar);
    return out;
}

ERL_NIF_TERM
{{ p }}_identity_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    return {{ p }}_make_point(env, {{ api }}_point_identity);
}

ERL_NIF_TERM
{{ p }}_base_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    return {{ p }}_make_point(env, {{ api }}_point_base);
}

ERL_NIF_TERM
{{ p }}_point_is_valid_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ api }}_point_t point;
    int valid = argc == 1 && {{ p }}_get_point(env, argv[0], point);
    {{ api }}_point_destroy(point);
    return valid ? ATOM(true) : ATOM(false);
}

ERL_NIF_TERM
{{ p }}_scalar_is_canonical_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ api }}_scalar_t scalar;
    int valid = argc == 1 && {{ p }}_get_scalar(env, argv[0], scalar);
    {{ api }}_scalar_destroy(scalar);
    return valid ? ATOM(true) : ATOM(false);
}

ERL_NIF_TERM
{{ p }}_point_eq_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ api }}_point_t a, b;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && {{ p }}_get_point(env, argv[0], a) && {{ p }}_get_point(env, argv[1], b)) {
        out = {{ api }}_point_eq(a, b) == DECAF_TRUE ? ATOM(true) : ATOM(false);
    }
    {{ api }}_point_destroy(a);
    {{ api }}_point_destroy(b);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

static ERL_NIF_TERM
{{ p }}_point_binary(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int subtract)
{
    {{ api }}_point_t a, b, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && {{ p }}_get_point(env, argv[0], a) && {{ p }}_get_point(env, argv[1], b)) {
        if (subtract)
            {{ api }}_point_sub(result, a, b);
        else
            {{ api }}_point_add(result, a, b);
        out = {{ p }}_make_point(env, result);
    }
    {{ api }}_point_destroy(a);
    {{ api }}_point_destroy(b);
    {{ api }}_point_destroy(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_point_add_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_point_binary(env, argc, argv, 0);
}
ERL_NIF_TERM
{{ p }}_point_sub_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_point_binary(env, argc, argv, 1);
}

static ERL_NIF_TERM
{{ p }}_point_unary(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int negate)
{
    {{ api }}_point_t point, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && {{ p }}_get_point(env, argv[0], point)) {
        if (negate)
            {{ api }}_point_negate(result, point);
        else
            {{ api }}_point_double(result, point);
        out = {{ p }}_make_point(env, result);
    }
    {{ api }}_point_destroy(point);
    {{ api }}_point_destroy(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_point_negate_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_point_unary(env, argc, argv, 1);
}
ERL_NIF_TERM
{{ p }}_point_double_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_point_unary(env, argc, argv, 0);
}

ERL_NIF_TERM
{{ p }}_scalar_reduce_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary bin;
    {{ api }}_scalar_t scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && enif_inspect_binary(env, argv[0], &bin)) {
        {{ api }}_scalar_decode_long(scalar, bin.data, bin.size);
        out = {{ p }}_make_scalar(env, scalar);
    }
    {{ api }}_scalar_destroy(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

static ERL_NIF_TERM
{{ p }}_scalar_binary(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int operation)
{
    {{ api }}_scalar_t a, b, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && {{ p }}_get_scalar(env, argv[0], a) && {{ p }}_get_scalar(env, argv[1], b)) {
        switch (operation) {
        case 0:
            {{ api }}_scalar_add(result, a, b);
            break;
        case 1:
            {{ api }}_scalar_sub(result, a, b);
            break;
        default:
            {{ api }}_scalar_mul(result, a, b);
            break;
        }
        out = {{ p }}_make_scalar(env, result);
    }
    {{ api }}_scalar_destroy(a);
    {{ api }}_scalar_destroy(b);
    {{ api }}_scalar_destroy(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_scalar_add_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_scalar_binary(env, argc, argv, 0);
}
ERL_NIF_TERM
{{ p }}_scalar_sub_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_scalar_binary(env, argc, argv, 1);
}
ERL_NIF_TERM
{{ p }}_scalar_mul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_scalar_binary(env, argc, argv, 2);
}

static ERL_NIF_TERM
{{ p }}_scalar_unary(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int operation)
{
    {{ api }}_scalar_t scalar, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && {{ p }}_get_scalar(env, argv[0], scalar)) {
        decaf_error_t success = DECAF_SUCCESS;
        switch (operation) {
        case 0:
            {{ api }}_scalar_sub(result, {{ api }}_scalar_zero, scalar);
            break;
        case 1:
            {{ api }}_scalar_halve(result, scalar);
            break;
        default:
            success = {{ api }}_scalar_invert(result, scalar);
            break;
        }
        out = success == DECAF_SUCCESS ? {{ p }}_make_scalar(env, result) : ATOM(error);
    }
    {{ api }}_scalar_destroy(scalar);
    {{ api }}_scalar_destroy(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_scalar_negate_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_scalar_unary(env, argc, argv, 0);
}
ERL_NIF_TERM
{{ p }}_scalar_halve_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_scalar_unary(env, argc, argv, 1);
}
ERL_NIF_TERM
{{ p }}_scalar_invert_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_scalar_unary(env, argc, argv, 2);
}

ERL_NIF_TERM
{{ p }}_point_scalarmul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ api }}_point_t point, result;
    {{ api }}_scalar_t scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && {{ p }}_get_point(env, argv[0], point) && {{ p }}_get_scalar(env, argv[1], scalar)) {
        {{ api }}_point_scalarmul(result, point, scalar);
        out = {{ p }}_make_point(env, result);
    }
    {{ api }}_point_destroy(point);
    {{ api }}_point_destroy(result);
    {{ api }}_scalar_destroy(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_base_scalarmul_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ api }}_point_t result;
    {{ api }}_scalar_t scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && {{ p }}_get_scalar(env, argv[0], scalar)) {
        {{ api }}_precomputed_scalarmul(result, {{ api }}_precomputed_base, scalar);
        out = {{ p }}_make_point(env, result);
    }
    {{ api }}_point_destroy(result);
    {{ api }}_scalar_destroy(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_point_double_scalarmul_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ api }}_point_t a, b, result;
    {{ api }}_scalar_t sa, sb;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 4 && {{ p }}_get_point(env, argv[0], a) && {{ p }}_get_scalar(env, argv[1], sa) &&
        {{ p }}_get_point(env, argv[2], b) && {{ p }}_get_scalar(env, argv[3], sb)) {
        {{ api }}_point_double_scalarmul(result, a, sa, b, sb);
        out = {{ p }}_make_point(env, result);
    }
    {{ api }}_point_destroy(a);
    {{ api }}_point_destroy(b);
    {{ api }}_point_destroy(result);
    {{ api }}_scalar_destroy(sa);
    {{ api }}_scalar_destroy(sb);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

static ERL_NIF_TERM
{{ p }}_from_hash(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int uniform)
{
    ErlNifBinary bin;
    {{ api }}_point_t point;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && enif_inspect_binary(env, argv[0], &bin) && bin.size == {{ group.point_bytes }} * (uniform ? 2 : 1)) {
        if (uniform)
            {{ api }}_point_from_hash_uniform(point, bin.data);
        else
            {{ api }}_point_from_hash_nonuniform(point, bin.data);
        out = {{ p }}_make_point(env, point);
    }
    {{ api }}_point_destroy(point);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_point_from_hash_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_from_hash(env, argc, argv, 1);
}
ERL_NIF_TERM
{{ p }}_point_from_hash_nonuniform_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_from_hash(env, argc, argv, 0);
}

ERL_NIF_TERM
{{ p }}_precompute_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ api }}_point_t point;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && {{ p }}_get_point(env, argv[0], point)) {
        {{ p }}_precomputed_t *ctx = enif_alloc_resource({{ p }}_precomputed_type, sizeof(*ctx));
        if (ctx == NULL) {
            out = EXCP_ERROR(env, "Cannot allocate precomputed resource");
        } else {
            size_t alignment = {{ api }}_alignof_precomputed_s;
            size_t size = {{ api }}_sizeof_precomputed_s;
            ctx->table = NULL;
            ctx->allocation = enif_alloc(size + alignment - 1);
            if (ctx->allocation == NULL) {
                out = EXCP_ERROR(env, "Cannot allocate precomputed table");
            } else {
                uintptr_t aligned = ((uintptr_t)ctx->allocation + alignment - 1) & ~((uintptr_t)alignment - 1);
                ctx->table = (void *)aligned;
                {{ api }}_precompute(ctx->table, point);
                out = enif_make_resource(env, ctx);
            }
            enif_release_resource(ctx);
        }
    }
    {{ api }}_point_destroy(point);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
{{ p }}_precomputed_scalarmul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_precomputed_t * ctx;
    {{ api }}_point_t result;
    {{ api }}_scalar_t scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && enif_get_resource(env, argv[0], {{ p }}_precomputed_type, (void **)&ctx) &&
        {{ p }}_get_scalar(env, argv[1], scalar)) {
        {{ api }}_precomputed_scalarmul(result, ctx->table, scalar);
        out = {{ p }}_make_point(env, result);
    }
    {{ api }}_point_destroy(result);
    {{ api }}_scalar_destroy(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}
{% endmacro %}
