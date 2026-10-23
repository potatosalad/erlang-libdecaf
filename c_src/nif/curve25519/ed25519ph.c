#include "ed25519ph.h"
#include "ed25519.h"

/* Signing and verification have distinct resources. Each state owns its
 * prehash and context; a signing state also retains its keypair resource.
 * Published states are immutable, including across finalization. */
typedef struct {
    decaf_ed25519_prehash_ctx_t *hash;
    uint8_t context[255];
    uint8_t context_len;
} libdecaf_nif_ed25519ph_prehash_t;

typedef struct {
    libdecaf_nif_ed25519ph_prehash_t prehash;
    libdecaf_nif_ed25519_keypair_t *keypair;
} libdecaf_nif_ed25519ph_sign_t;

typedef struct {
    libdecaf_nif_ed25519ph_prehash_t prehash;
    uint8_t signature[DECAF_EDDSA_25519_SIGNATURE_BYTES];
    uint8_t public_key[DECAF_EDDSA_25519_PUBLIC_BYTES];
} libdecaf_nif_ed25519ph_verify_t;

typedef struct {
    void *state;
    decaf_ed25519_prehash_ctx_t *hash;
    ErlNifEnv *work_env;
    ErlNifBinary input;
    size_t offset;
} libdecaf_nif_ed25519ph_update_t;

static ErlNifResourceType *libdecaf_nif_ed25519ph_sign_resource_type;
static ErlNifResourceType *libdecaf_nif_ed25519ph_verify_resource_type;
static ErlNifResourceType *libdecaf_nif_ed25519ph_update_resource_type;

static void
libdecaf_nif_ed25519ph_sign_dtor(ErlNifEnv *env, void *object)
{
    (void)env;
    libdecaf_nif_ed25519ph_sign_t *state = object;
    decaf_ed25519_prehash_destroy(*state->prehash.hash);
    if (state->keypair != NULL)
        enif_release_resource(state->keypair);
    decaf_bzero(state, enif_sizeof_resource(state));
}

static void
libdecaf_nif_ed25519ph_verify_dtor(ErlNifEnv *env, void *object)
{
    (void)env;
    libdecaf_nif_ed25519ph_verify_t *state = object;
    decaf_ed25519_prehash_destroy(*state->prehash.hash);
    decaf_bzero(state, enif_sizeof_resource(state));
}

static void
libdecaf_nif_ed25519ph_update_dtor(ErlNifEnv *env, void *object)
{
    (void)env;
    libdecaf_nif_ed25519ph_update_t *trap = object;
    if (trap->state != NULL)
        enif_release_resource(trap->state);
    if (trap->work_env != NULL)
        enif_free_env(trap->work_env);
    decaf_bzero(trap, sizeof(*trap));
}

int
libdecaf_nif_ed25519ph_load(ErlNifEnv *env)
{
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    libdecaf_nif_ed25519ph_sign_resource_type =
        enif_open_resource_type(env, "libdecaf_nif", "ed25519ph_sign", libdecaf_nif_ed25519ph_sign_dtor, flags, NULL);
    libdecaf_nif_ed25519ph_verify_resource_type =
        enif_open_resource_type(env, "libdecaf_nif", "ed25519ph_verify", libdecaf_nif_ed25519ph_verify_dtor, flags, NULL);
    libdecaf_nif_ed25519ph_update_resource_type =
        enif_open_resource_type(env, "libdecaf_nif", "ed25519ph_update", libdecaf_nif_ed25519ph_update_dtor, flags, NULL);
    return libdecaf_nif_ed25519ph_sign_resource_type != NULL && libdecaf_nif_ed25519ph_verify_resource_type != NULL &&
                   libdecaf_nif_ed25519ph_update_resource_type != NULL
               ? 0
               : -1;
}

static void *
libdecaf_nif_ed25519ph_alloc(ErlNifResourceType *type, size_t header_size)
{
    /* A resource payload may be only word-aligned. Align the prehash inside
     * its allocation, independently of the resource's header alignment. */
    size_t alignment = _Alignof(decaf_ed25519_prehash_ctx_t);
    size_t size = header_size + sizeof(decaf_ed25519_prehash_ctx_t) + alignment - 1;
    libdecaf_nif_ed25519ph_prehash_t *state = enif_alloc_resource(type, size);
    if (state != NULL) {
        decaf_bzero(state, size);
        uintptr_t start = (uintptr_t)state + header_size;
        state->hash = (void *)(start + (alignment - start % alignment) % alignment);
        decaf_ed25519_prehash_init(*state->hash);
    }
    return state;
}

static ERL_NIF_TERM
libdecaf_nif_ed25519ph_publish(ErlNifEnv *env, void *state)
{
    ERL_NIF_TERM result = enif_make_resource(env, state);
    enif_release_resource(state);
    return result;
}

static ERL_NIF_TERM
libdecaf_nif_ed25519ph_sign_begin(ErlNifEnv *env, libdecaf_nif_ed25519_keypair_t *keypair, const ErlNifBinary *context)
{
    libdecaf_nif_ed25519ph_sign_t *state = libdecaf_nif_ed25519ph_alloc(libdecaf_nif_ed25519ph_sign_resource_type, sizeof(*state));
    if (state == NULL)
        return EXCP_ERROR(env, "Cannot allocate ed25519ph signing state");
    enif_keep_resource(keypair);
    state->keypair = keypair;
    state->prehash.context_len = (uint8_t)context->size;
    if (context->size != 0)
        memcpy(state->prehash.context, context->data, context->size);
    return libdecaf_nif_ed25519ph_publish(env, state);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_sign_init_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1)
        return enif_make_badarg(env);
    ERL_NIF_TERM context;
    (void)enif_make_new_binary(env, 0, &context);
    ERL_NIF_TERM args[] = {argv[0], context};
    return libdecaf_nif_ed25519ph_sign_init_2(env, 2, args);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_sign_init_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary encoded, context;
    if (argc != 2 || !enif_inspect_binary(env, argv[0], &encoded) ||
        encoded.size != DECAF_EDDSA_25519_PRIVATE_BYTES + DECAF_EDDSA_25519_PUBLIC_BYTES)
        return EXCP_BADARG(env, "Signing key must be the ed25519 seed followed by its public key");
    if (!enif_inspect_binary(env, argv[1], &context) || context.size > 255)
        return EXCP_BADARG(env, "Context must be a binary of at most 255 bytes");
    libdecaf_nif_ed25519_keypair_t *keypair = libdecaf_nif_ed25519_keypair_from_secret(encoded.data);
    if (keypair == NULL)
        return EXCP_ERROR(env, "Cannot allocate ed25519 keypair");
    uint8_t public_key[DECAF_EDDSA_25519_PUBLIC_BYTES];
    decaf_ed25519_keypair_extract_public_key(public_key, keypair->inner);
    if (decaf_memeq(public_key, encoded.data + DECAF_EDDSA_25519_PRIVATE_BYTES, sizeof(public_key)) != DECAF_TRUE) {
        enif_release_resource(keypair);
        return EXCP_ERROR(env, "Signing key seed and public key do not match");
    }
    ERL_NIF_TERM result = libdecaf_nif_ed25519ph_sign_begin(env, keypair, &context);
    enif_release_resource(keypair);
    return result;
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_keypair_sign_init_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1)
        return enif_make_badarg(env);
    ERL_NIF_TERM context;
    (void)enif_make_new_binary(env, 0, &context);
    ERL_NIF_TERM args[] = {argv[0], context};
    return libdecaf_nif_ed25519ph_keypair_sign_init_2(env, 2, args);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_keypair_sign_init_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519_keypair_t *keypair;
    ErlNifBinary context;
    if (argc != 2 || (keypair = libdecaf_nif_ed25519_get_keypair(env, argv[0])) == NULL)
        return EXCP_BADARG(env, "Expected an ed25519 keypair resource");
    if (!enif_inspect_binary(env, argv[1], &context) || context.size > 255)
        return EXCP_BADARG(env, "Context must be a binary of at most 255 bytes");
    return libdecaf_nif_ed25519ph_sign_begin(env, keypair, &context);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_verify_init_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2)
        return enif_make_badarg(env);
    ERL_NIF_TERM context;
    (void)enif_make_new_binary(env, 0, &context);
    ERL_NIF_TERM args[] = {argv[0], argv[1], context};
    return libdecaf_nif_ed25519ph_verify_init_3(env, 3, args);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_verify_init_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary signature, public_key, context;
    if (argc != 3 || !enif_inspect_binary(env, argv[0], &signature) || signature.size != DECAF_EDDSA_25519_SIGNATURE_BYTES ||
        !enif_inspect_binary(env, argv[1], &public_key) || public_key.size != DECAF_EDDSA_25519_PUBLIC_BYTES)
        return EXCP_BADARG(env, "Expected an ed25519ph signature and public key");
    if (!enif_inspect_binary(env, argv[2], &context) || context.size > 255)
        return EXCP_BADARG(env, "Context must be a binary of at most 255 bytes");
    libdecaf_nif_ed25519ph_verify_t *state =
        libdecaf_nif_ed25519ph_alloc(libdecaf_nif_ed25519ph_verify_resource_type, sizeof(*state));
    if (state == NULL)
        return EXCP_ERROR(env, "Cannot allocate ed25519ph verification state");
    memcpy(state->signature, signature.data, signature.size);
    memcpy(state->public_key, public_key.data, public_key.size);
    state->prehash.context_len = (uint8_t)context.size;
    if (context.size != 0)
        memcpy(state->prehash.context, context.data, context.size);
    return libdecaf_nif_ed25519ph_publish(env, state);
}

static ERL_NIF_TERM
libdecaf_nif_ed25519ph_update_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519ph_update_t *trap;
    if (argc != 1 || !enif_get_resource(env, argv[0], libdecaf_nif_ed25519ph_update_resource_type, (void **)&trap) ||
        trap->state == NULL)
        return enif_make_badarg(env);
    size_t budget = REDUCTIONS_UNTIL_YCF_YIELD();
    size_t take = trap->input.size - trap->offset;
    if (take > budget)
        take = budget;
    if (take != 0)
        decaf_ed25519_prehash_update(*trap->hash, trap->input.data + trap->offset, take);
    trap->offset += take;
    if (trap->offset != trap->input.size) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_ed25519ph_update_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 libdecaf_nif_ed25519ph_update_continue, argc, argv);
    }
    ERL_NIF_TERM result = enif_make_resource(env, trap->state);
    enif_release_resource(trap->state);
    trap->state = NULL;
    trap->hash = NULL;
    enif_free_env(trap->work_env);
    trap->work_env = NULL;
    enif_consume_timeslice(env, (int)((100 * take + budget - 1) / budget));
    return result;
}

/* Takes the private clone's reference, including when allocation fails. The
 * copied input environment remains alive until completion or cancellation. */
static ERL_NIF_TERM
libdecaf_nif_ed25519ph_update(ErlNifEnv *env, void *state, ERL_NIF_TERM input)
{
    libdecaf_nif_ed25519ph_update_t *trap = enif_alloc_resource(libdecaf_nif_ed25519ph_update_resource_type, sizeof(*trap));
    if (trap == NULL) {
        enif_release_resource(state);
        return EXCP_ERROR(env, "Cannot allocate ed25519ph update continuation");
    }
    decaf_bzero(trap, sizeof(*trap));
    trap->state = state;
    trap->hash = ((libdecaf_nif_ed25519ph_prehash_t *)state)->hash;
    trap->work_env = enif_alloc_env();
    if (trap->work_env == NULL) {
        enif_release_resource(trap);
        return EXCP_ERROR(env, "Cannot allocate ed25519ph input environment");
    }
    ERL_NIF_TERM copied_input = enif_make_copy(trap->work_env, input);
    if (!enif_inspect_iolist_as_binary(trap->work_env, copied_input, &trap->input)) {
        enif_release_resource(trap);
        return EXCP_BADARG(env, "Input must be iodata");
    }
    ERL_NIF_TERM args[] = {enif_make_resource(env, trap)};
    enif_release_resource(trap);
    return libdecaf_nif_ed25519ph_update_continue(env, 1, args);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_sign_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519ph_sign_t *state;
    if (argc != 2 || !enif_get_resource(env, argv[0], libdecaf_nif_ed25519ph_sign_resource_type, (void **)&state))
        return EXCP_BADARG(env, "Expected an ed25519ph signing state");
    libdecaf_nif_ed25519ph_sign_t *copy = libdecaf_nif_ed25519ph_alloc(libdecaf_nif_ed25519ph_sign_resource_type, sizeof(*copy));
    if (copy == NULL)
        return EXCP_ERROR(env, "Cannot copy ed25519ph signing state");
    decaf_ed25519_prehash_ctx_t *hash = copy->prehash.hash;
    memcpy(copy, state, sizeof(*copy));
    copy->prehash.hash = hash;
    memcpy(hash, state->prehash.hash, sizeof(*hash));
    enif_keep_resource(copy->keypair);
    return libdecaf_nif_ed25519ph_update(env, copy, argv[1]);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_verify_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519ph_verify_t *state;
    if (argc != 2 || !enif_get_resource(env, argv[0], libdecaf_nif_ed25519ph_verify_resource_type, (void **)&state))
        return EXCP_BADARG(env, "Expected an ed25519ph verification state");
    libdecaf_nif_ed25519ph_verify_t *copy =
        libdecaf_nif_ed25519ph_alloc(libdecaf_nif_ed25519ph_verify_resource_type, sizeof(*copy));
    if (copy == NULL)
        return EXCP_ERROR(env, "Cannot copy ed25519ph verification state");
    decaf_ed25519_prehash_ctx_t *hash = copy->prehash.hash;
    memcpy(copy, state, sizeof(*copy));
    copy->prehash.hash = hash;
    memcpy(hash, state->prehash.hash, sizeof(*hash));
    return libdecaf_nif_ed25519ph_update(env, copy, argv[1]);
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_sign_final_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519ph_sign_t *state;
    if (argc != 1 || !enif_get_resource(env, argv[0], libdecaf_nif_ed25519ph_sign_resource_type, (void **)&state))
        return EXCP_BADARG(env, "Expected an ed25519ph signing state");
    ERL_NIF_TERM result;
    uint8_t *signature = enif_make_new_binary(env, DECAF_EDDSA_25519_SIGNATURE_BYTES, &result);
    if (signature == NULL)
        return EXCP_ERROR(env, "Cannot allocate ed25519ph signature");
    /* The upstream prehash signing API finalizes its own copy of the hash. */
    decaf_ed25519_keypair_sign_prehash(signature, state->keypair->inner, *state->prehash.hash, state->prehash.context,
                                       state->prehash.context_len);
    return result;
}

ERL_NIF_TERM
libdecaf_nif_ed25519ph_verify_final_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_ed25519ph_verify_t *state;
    if (argc != 1 || !enif_get_resource(env, argv[0], libdecaf_nif_ed25519ph_verify_resource_type, (void **)&state))
        return EXCP_BADARG(env, "Expected an ed25519ph verification state");
    decaf_error_t result = decaf_ed25519_verify_prehash(state->signature, state->public_key, *state->prehash.hash,
                                                        state->prehash.context, state->prehash.context_len);
    return result == DECAF_SUCCESS ? ATOM(true) : ATOM(false);
}
