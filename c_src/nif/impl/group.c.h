/* Included once for each prime-order group. Points and scalars cross the
 * NIF boundary only in canonical wire format. Stack points retain the
 * alignment required by upstream; precomputed tables are aligned separately.
 * ATOM(badarg) is a sentinel: raise the exception after wiping temporaries. */

typedef struct {
    void *allocation;
    GROUP_API(_precomputed_s) * table;
} GROUP_NIF(_precomputed_t);

static ErlNifResourceType *GROUP_NIF(_precomputed_type);

static void
GROUP_NIF(_precomputed_dtor)(ErlNifEnv *env, void *obj)
{
    GROUP_NIF(_precomputed_t) *ctx = obj;
    (void)env;
    if (ctx->table != NULL) {
        GROUP_API(_precomputed_destroy)(ctx->table);
    }
    if (ctx->allocation != NULL)
        enif_free(ctx->allocation);
}

static int
GROUP_NIF(_get_point)(ErlNifEnv *env, ERL_NIF_TERM term, GROUP_API(_point_t) point)
{
    ErlNifBinary bin;
    return enif_inspect_binary(env, term, &bin) && bin.size == GROUP_POINT_BYTES &&
           GROUP_API(_point_decode)(point, bin.data, DECAF_TRUE) == DECAF_SUCCESS;
}

static int
GROUP_NIF(_get_scalar)(ErlNifEnv *env, ERL_NIF_TERM term, GROUP_API(_scalar_t) scalar)
{
    ErlNifBinary bin;
    return enif_inspect_binary(env, term, &bin) && bin.size == GROUP_SCALAR_BYTES &&
           GROUP_API(_scalar_decode)(scalar, bin.data) == DECAF_SUCCESS;
}

static ERL_NIF_TERM
GROUP_NIF(_make_point)(ErlNifEnv *env, const GROUP_API(_point_t) point)
{
    ERL_NIF_TERM out;
    unsigned char *bytes = enif_make_new_binary(env, GROUP_POINT_BYTES, &out);
    if (bytes == NULL)
        return EXCP_ERROR(env, "Cannot allocate point binary");
    GROUP_API(_point_encode)(bytes, point);
    return out;
}

static ERL_NIF_TERM
GROUP_NIF(_make_scalar)(ErlNifEnv *env, const GROUP_API(_scalar_t) scalar)
{
    ERL_NIF_TERM out;
    unsigned char *bytes = enif_make_new_binary(env, GROUP_SCALAR_BYTES, &out);
    if (bytes == NULL)
        return EXCP_ERROR(env, "Cannot allocate scalar binary");
    GROUP_API(_scalar_encode)(bytes, scalar);
    return out;
}

ERL_NIF_TERM
GROUP_NIF(_identity_0)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    return GROUP_NIF(_make_point)(env, GROUP_API(_point_identity));
}

ERL_NIF_TERM
GROUP_NIF(_base_0)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    return GROUP_NIF(_make_point)(env, GROUP_API(_point_base));
}

ERL_NIF_TERM
GROUP_NIF(_point_is_valid_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_API(_point_t) point;
    int valid = argc == 1 && GROUP_NIF(_get_point)(env, argv[0], point);
    GROUP_API(_point_destroy)(point);
    return valid ? ATOM(true) : ATOM(false);
}

ERL_NIF_TERM
GROUP_NIF(_scalar_is_canonical_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_API(_scalar_t) scalar;
    int valid = argc == 1 && GROUP_NIF(_get_scalar)(env, argv[0], scalar);
    GROUP_API(_scalar_destroy)(scalar);
    return valid ? ATOM(true) : ATOM(false);
}

ERL_NIF_TERM
GROUP_NIF(_point_eq_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_API(_point_t) a, b;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && GROUP_NIF(_get_point)(env, argv[0], a) && GROUP_NIF(_get_point)(env, argv[1], b)) {
        out = GROUP_API(_point_eq)(a, b) == DECAF_TRUE ? ATOM(true) : ATOM(false);
    }
    GROUP_API(_point_destroy)(a);
    GROUP_API(_point_destroy)(b);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

static ERL_NIF_TERM
GROUP_NIF(_point_binary)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int subtract)
{
    GROUP_API(_point_t) a, b, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && GROUP_NIF(_get_point)(env, argv[0], a) && GROUP_NIF(_get_point)(env, argv[1], b)) {
        if (subtract)
            GROUP_API(_point_sub)(result, a, b);
        else
            GROUP_API(_point_add)(result, a, b);
        out = GROUP_NIF(_make_point)(env, result);
    }
    GROUP_API(_point_destroy)(a);
    GROUP_API(_point_destroy)(b);
    GROUP_API(_point_destroy)(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_point_add_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_point_binary)(env, argc, argv, 0);
}
ERL_NIF_TERM
GROUP_NIF(_point_sub_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_point_binary)(env, argc, argv, 1);
}

static ERL_NIF_TERM
GROUP_NIF(_point_unary)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int negate)
{
    GROUP_API(_point_t) point, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && GROUP_NIF(_get_point)(env, argv[0], point)) {
        if (negate)
            GROUP_API(_point_negate)(result, point);
        else
            GROUP_API(_point_double)(result, point);
        out = GROUP_NIF(_make_point)(env, result);
    }
    GROUP_API(_point_destroy)(point);
    GROUP_API(_point_destroy)(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_point_negate_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_point_unary)(env, argc, argv, 1);
}
ERL_NIF_TERM
GROUP_NIF(_point_double_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_point_unary)(env, argc, argv, 0);
}

ERL_NIF_TERM
GROUP_NIF(_scalar_reduce_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary bin;
    GROUP_API(_scalar_t) scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && enif_inspect_binary(env, argv[0], &bin)) {
        GROUP_API(_scalar_decode_long)(scalar, bin.data, bin.size);
        out = GROUP_NIF(_make_scalar)(env, scalar);
    }
    GROUP_API(_scalar_destroy)(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

static ERL_NIF_TERM
GROUP_NIF(_scalar_binary)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int operation)
{
    GROUP_API(_scalar_t) a, b, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && GROUP_NIF(_get_scalar)(env, argv[0], a) && GROUP_NIF(_get_scalar)(env, argv[1], b)) {
        switch (operation) {
        case 0:
            GROUP_API(_scalar_add)(result, a, b);
            break;
        case 1:
            GROUP_API(_scalar_sub)(result, a, b);
            break;
        default:
            GROUP_API(_scalar_mul)(result, a, b);
            break;
        }
        out = GROUP_NIF(_make_scalar)(env, result);
    }
    GROUP_API(_scalar_destroy)(a);
    GROUP_API(_scalar_destroy)(b);
    GROUP_API(_scalar_destroy)(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_scalar_add_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_scalar_binary)(env, argc, argv, 0);
}
ERL_NIF_TERM
GROUP_NIF(_scalar_sub_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_scalar_binary)(env, argc, argv, 1);
}
ERL_NIF_TERM
GROUP_NIF(_scalar_mul_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_scalar_binary)(env, argc, argv, 2);
}

static ERL_NIF_TERM
GROUP_NIF(_scalar_unary)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int operation)
{
    GROUP_API(_scalar_t) scalar, result;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && GROUP_NIF(_get_scalar)(env, argv[0], scalar)) {
        decaf_error_t success = DECAF_SUCCESS;
        switch (operation) {
        case 0:
            GROUP_API(_scalar_sub)(result, GROUP_API(_scalar_zero), scalar);
            break;
        case 1:
            GROUP_API(_scalar_halve)(result, scalar);
            break;
        default:
            success = GROUP_API(_scalar_invert)(result, scalar);
            break;
        }
        out = success == DECAF_SUCCESS ? GROUP_NIF(_make_scalar)(env, result) : ATOM(error);
    }
    GROUP_API(_scalar_destroy)(scalar);
    GROUP_API(_scalar_destroy)(result);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_scalar_negate_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_scalar_unary)(env, argc, argv, 0);
}
ERL_NIF_TERM
GROUP_NIF(_scalar_halve_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_scalar_unary)(env, argc, argv, 1);
}
ERL_NIF_TERM
GROUP_NIF(_scalar_invert_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_scalar_unary)(env, argc, argv, 2);
}

ERL_NIF_TERM
GROUP_NIF(_point_scalarmul_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_API(_point_t) point, result;
    GROUP_API(_scalar_t) scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && GROUP_NIF(_get_point)(env, argv[0], point) && GROUP_NIF(_get_scalar)(env, argv[1], scalar)) {
        GROUP_API(_point_scalarmul)(result, point, scalar);
        out = GROUP_NIF(_make_point)(env, result);
    }
    GROUP_API(_point_destroy)(point);
    GROUP_API(_point_destroy)(result);
    GROUP_API(_scalar_destroy)(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_base_scalarmul_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_API(_point_t) result;
    GROUP_API(_scalar_t) scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && GROUP_NIF(_get_scalar)(env, argv[0], scalar)) {
        GROUP_API(_precomputed_scalarmul)(result, GROUP_API(_precomputed_base), scalar);
        out = GROUP_NIF(_make_point)(env, result);
    }
    GROUP_API(_point_destroy)(result);
    GROUP_API(_scalar_destroy)(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_point_double_scalarmul_4)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_API(_point_t) a, b, result;
    GROUP_API(_scalar_t) sa, sb;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 4 && GROUP_NIF(_get_point)(env, argv[0], a) && GROUP_NIF(_get_scalar)(env, argv[1], sa) &&
        GROUP_NIF(_get_point)(env, argv[2], b) && GROUP_NIF(_get_scalar)(env, argv[3], sb)) {
        GROUP_API(_point_double_scalarmul)(result, a, sa, b, sb);
        out = GROUP_NIF(_make_point)(env, result);
    }
    GROUP_API(_point_destroy)(a);
    GROUP_API(_point_destroy)(b);
    GROUP_API(_point_destroy)(result);
    GROUP_API(_scalar_destroy)(sa);
    GROUP_API(_scalar_destroy)(sb);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

static ERL_NIF_TERM
GROUP_NIF(_from_hash)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], int uniform)
{
    ErlNifBinary bin;
    GROUP_API(_point_t) point;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && enif_inspect_binary(env, argv[0], &bin) && bin.size == GROUP_POINT_BYTES * (uniform ? 2 : 1)) {
        if (uniform)
            GROUP_API(_point_from_hash_uniform)(point, bin.data);
        else
            GROUP_API(_point_from_hash_nonuniform)(point, bin.data);
        out = GROUP_NIF(_make_point)(env, point);
    }
    GROUP_API(_point_destroy)(point);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_point_from_hash_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_from_hash)(env, argc, argv, 1);
}
ERL_NIF_TERM
GROUP_NIF(_point_from_hash_nonuniform_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return GROUP_NIF(_from_hash)(env, argc, argv, 0);
}

ERL_NIF_TERM
GROUP_NIF(_precompute_1)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_API(_point_t) point;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 1 && GROUP_NIF(_get_point)(env, argv[0], point)) {
        GROUP_NIF(_precomputed_t) *ctx = enif_alloc_resource(GROUP_NIF(_precomputed_type), sizeof(*ctx));
        if (ctx == NULL) {
            out = EXCP_ERROR(env, "Cannot allocate precomputed resource");
        } else {
            size_t alignment = GROUP_API(_alignof_precomputed_s);
            size_t size = GROUP_API(_sizeof_precomputed_s);
            ctx->table = NULL;
            ctx->allocation = enif_alloc(size + alignment - 1);
            if (ctx->allocation == NULL) {
                out = EXCP_ERROR(env, "Cannot allocate precomputed table");
            } else {
                uintptr_t aligned = ((uintptr_t)ctx->allocation + alignment - 1) & ~((uintptr_t)alignment - 1);
                ctx->table = (void *)aligned;
                GROUP_API(_precompute)(ctx->table, point);
                out = enif_make_resource(env, ctx);
            }
            enif_release_resource(ctx);
        }
    }
    GROUP_API(_point_destroy)(point);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}

ERL_NIF_TERM
GROUP_NIF(_precomputed_scalarmul_2)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    GROUP_NIF(_precomputed_t) * ctx;
    GROUP_API(_point_t) result;
    GROUP_API(_scalar_t) scalar;
    ERL_NIF_TERM out = ATOM(badarg);
    if (argc == 2 && enif_get_resource(env, argv[0], GROUP_NIF(_precomputed_type), (void **)&ctx) &&
        GROUP_NIF(_get_scalar)(env, argv[1], scalar)) {
        GROUP_API(_precomputed_scalarmul)(result, ctx->table, scalar);
        out = GROUP_NIF(_make_point)(env, result);
    }
    GROUP_API(_point_destroy)(result);
    GROUP_API(_scalar_destroy)(scalar);
    return out == ATOM(badarg) ? enif_make_badarg(env) : out;
}
