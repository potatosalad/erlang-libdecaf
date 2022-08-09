// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libdecaf_nif.h"

#include "csprng.h"
#include "hash.h"
#include "xof.h"

#include <unistd.h>

/* Global Variables */

ErlNifResourceType *libdecaf_nif_trap_resource_type = NULL;
ErlNifResourceType *libdecaf_nif_csprng_resource_type = NULL;
ErlNifResourceType *libdecaf_nif_hash_resource_type = NULL;
ErlNifResourceType *libdecaf_nif_xof_resource_type = NULL;

static libdecaf_nif_atom_table_t libdecaf_nif_atom_table_internal;

libdecaf_nif_atom_table_t *libdecaf_nif_atom_table = &libdecaf_nif_atom_table_internal;

/* Resource Type Functions (Declarations) */

static void libdecaf_nif_trap_dtor(ErlNifEnv *caller_env, void *obj);
static void libdecaf_nif_csprng_dtor(ErlNifEnv *caller_env, void *obj);
static void libdecaf_nif_hash_dtor(ErlNifEnv *caller_env, void *obj);
static void libdecaf_nif_xof_dtor(ErlNifEnv *caller_env, void *obj);

void
libdecaf_nif_trap_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_trap_t *trap = (void *)obj;
    if (trap != NULL) {
        XNIF_TRACE_F("libdecaf_nif_trap_dtor:%s:%d\n", __FILE__, __LINE__);
        if (trap->dtor != NULL) {
            (void)trap->dtor(caller_env, obj);
            trap->dtor = NULL;
        }
        if (trap->work_env != NULL) {
            (void)enif_free_env(trap->work_env);
            trap->work_env = NULL;
        }
    }
    return;
}

void
libdecaf_nif_csprng_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_csprng_ctx_t *ctx = (void *)obj;
    if (ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_csprng_dtor:%s:%d\n", __FILE__, __LINE__);
        (void)decaf_spongerng_destroy((void *)ctx);
    }
    return;
}

void
libdecaf_nif_hash_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_hash_ctx_t *ctx = (void *)obj;
    libdecaf_nif_hash_t *hash = NULL;
    if (ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_hash_dtor:%s:%d\n", __FILE__, __LINE__);
        hash = libdecaf_nif_hash_from_type(ctx->type);
        if (hash != NULL) {
            (void)hash->destroy((void *)ctx);
        }
    }
    return;
}

void
libdecaf_nif_xof_dtor(ErlNifEnv *caller_env, void *obj)
{
    libdecaf_nif_xof_ctx_t *ctx = (void *)obj;
    libdecaf_nif_xof_t *xof = NULL;
    if (ctx != NULL) {
        XNIF_TRACE_F("libdecaf_nif_xof_dtor:%s:%d\n", __FILE__, __LINE__);
        xof = libdecaf_nif_xof_from_type(ctx->type);
        if (xof != NULL) {
            (void)xof->destroy((void *)ctx);
        }
    }
    return;
}

/* Static Functions (Declarations) */

/* NIF Function Declarations */

/* decaf/ed255.h */
static ERL_NIF_TERM libdecaf_nif_ed25519_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed25519_sign_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed25519_sign_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed25519_verify_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed25519_verify_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed25519_convert_public_key_to_x25519_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed25519_convert_private_key_to_x25519_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
/* decaf/ed448.h */
static ERL_NIF_TERM libdecaf_nif_ed448_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed448_sign_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed448_sign_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed448_verify_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed448_verify_prehash_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed448_convert_public_key_to_x448_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_ed448_convert_private_key_to_x448_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
/* decaf/point_255.h */
static ERL_NIF_TERM libdecaf_nif_x25519_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_x25519_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
/* decaf/point_448.h */
static ERL_NIF_TERM libdecaf_nif_x448_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_x448_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
/* decaf/sha512.h */
/* decaf/shake.h */
#define HASH_DECLARATION(Id)                                                                                                       \
    static ERL_NIF_TERM libdecaf_nif_##Id##_hash_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                           \
    static ERL_NIF_TERM libdecaf_nif_##Id##_hash_init_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                      \
    static ERL_NIF_TERM libdecaf_nif_##Id##_hash_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                    \
    static ERL_NIF_TERM libdecaf_nif_##Id##_hash_final_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
HASH_DECLARATION(sha2_512)
HASH_DECLARATION(sha3_224)
HASH_DECLARATION(sha3_256)
HASH_DECLARATION(sha3_384)
HASH_DECLARATION(sha3_512)
HASH_DECLARATION(keccak_224)
HASH_DECLARATION(keccak_256)
HASH_DECLARATION(keccak_384)
HASH_DECLARATION(keccak_512)
#undef HASH_DECLARATION
#define XOF_DECLARATION(Id)                                                                                                        \
    static ERL_NIF_TERM libdecaf_nif_##Id##_xof_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                            \
    static ERL_NIF_TERM libdecaf_nif_##Id##_xof_init_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                       \
    static ERL_NIF_TERM libdecaf_nif_##Id##_xof_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                     \
    static ERL_NIF_TERM libdecaf_nif_##Id##_xof_output_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
XOF_DECLARATION(shake128)
XOF_DECLARATION(shake256)
#undef XOF_DECLARATION

/* NIF Function Definitions */

/* decaf/ed255.h */
#include "impl/ed255.c.h"
/* decaf/ed448.h */
#include "impl/ed448.c.h"
/* decaf/point_255.h */
#include "impl/point_255.c.h"
/* decaf/point_448.h */
#include "impl/point_448.c.h"
/* decaf/sha512.h */
/* decaf/shake.h */
#define HASH_DEFINITION(Id)                                                                                                        \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_hash_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                                \
    {                                                                                                                              \
        return libdecaf_nif_hash_2(&libdecaf_nif_hash_table->Id, env, argc, argv);                                                 \
    }                                                                                                                              \
                                                                                                                                   \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_hash_init_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                           \
    {                                                                                                                              \
        return libdecaf_nif_hash_init_0(&libdecaf_nif_hash_table->Id, env, argc, argv);                                            \
    }                                                                                                                              \
                                                                                                                                   \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_hash_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                         \
    {                                                                                                                              \
        return libdecaf_nif_hash_update_2(&libdecaf_nif_hash_table->Id, env, argc, argv);                                          \
    }                                                                                                                              \
                                                                                                                                   \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_hash_final_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                          \
    {                                                                                                                              \
        return libdecaf_nif_hash_final_2(&libdecaf_nif_hash_table->Id, env, argc, argv);                                           \
    }
HASH_DEFINITION(sha2_512)
HASH_DEFINITION(sha3_224)
HASH_DEFINITION(sha3_256)
HASH_DEFINITION(sha3_384)
HASH_DEFINITION(sha3_512)
HASH_DEFINITION(keccak_224)
HASH_DEFINITION(keccak_256)
HASH_DEFINITION(keccak_384)
HASH_DEFINITION(keccak_512)
#undef HASH_DEFINITION
#define XOF_DEFINITION(Id)                                                                                                         \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_xof_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                                 \
    {                                                                                                                              \
        return libdecaf_nif_xof_2(&libdecaf_nif_xof_table->Id, env, argc, argv);                                                   \
    }                                                                                                                              \
                                                                                                                                   \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_xof_init_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                            \
    {                                                                                                                              \
        return libdecaf_nif_xof_init_0(&libdecaf_nif_xof_table->Id, env, argc, argv);                                              \
    }                                                                                                                              \
                                                                                                                                   \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_xof_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                          \
    {                                                                                                                              \
        return libdecaf_nif_xof_update_2(&libdecaf_nif_xof_table->Id, env, argc, argv);                                            \
    }                                                                                                                              \
                                                                                                                                   \
    ERL_NIF_TERM                                                                                                                   \
    libdecaf_nif_##Id##_xof_output_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])                                          \
    {                                                                                                                              \
        return libdecaf_nif_xof_output_2(&libdecaf_nif_xof_table->Id, env, argc, argv);                                            \
    }
XOF_DEFINITION(shake128)
XOF_DEFINITION(shake256)
#undef XOF_DEFINITION

/* NIF Callbacks */

static ErlNifFunc libdecaf_nif_funcs[] = {
    /* decaf/ed255.h */
    {"ed25519_derive_public_key", 1, libdecaf_nif_ed25519_derive_public_key_1, ERL_NIF_NORMAL_JOB_BOUND},
    {"ed25519_sign", 5, libdecaf_nif_ed25519_sign_5, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed25519_sign_prehash", 4, libdecaf_nif_ed25519_sign_prehash_4, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed25519_verify", 5, libdecaf_nif_ed25519_verify_5, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed25519_verify_prehash", 4, libdecaf_nif_ed25519_verify_prehash_4, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed25519_convert_public_key_to_x25519", 1, libdecaf_nif_ed25519_convert_public_key_to_x25519_1, ERL_NIF_NORMAL_JOB_BOUND},
    {"ed25519_convert_private_key_to_x25519", 1, libdecaf_nif_ed25519_convert_private_key_to_x25519_1, ERL_NIF_NORMAL_JOB_BOUND},
    /* decaf/ed448.h */
    {"ed448_derive_public_key", 1, libdecaf_nif_ed448_derive_public_key_1, ERL_NIF_NORMAL_JOB_BOUND},
    {"ed448_sign", 5, libdecaf_nif_ed448_sign_5, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed448_sign_prehash", 4, libdecaf_nif_ed448_sign_prehash_4, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed448_verify", 5, libdecaf_nif_ed448_verify_5, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed448_verify_prehash", 4, libdecaf_nif_ed448_verify_prehash_4, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed448_convert_public_key_to_x448", 1, libdecaf_nif_ed448_convert_public_key_to_x448_1, ERL_NIF_NORMAL_JOB_BOUND},
    {"ed448_convert_private_key_to_x448", 1, libdecaf_nif_ed448_convert_private_key_to_x448_1, ERL_NIF_NORMAL_JOB_BOUND},
    /* decaf/point_255.h */
    {"x25519_derive_public_key", 1, libdecaf_nif_x25519_derive_public_key_1, ERL_NIF_NORMAL_JOB_BOUND},
    {"x25519", 2, libdecaf_nif_x25519_2, ERL_NIF_NORMAL_JOB_BOUND},
    {"x448_derive_public_key", 1, libdecaf_nif_x448_derive_public_key_1, ERL_NIF_NORMAL_JOB_BOUND},
    {"x448", 2, libdecaf_nif_x448_2, ERL_NIF_NORMAL_JOB_BOUND},
// clang-format off
/* decaf/sha512.h */
/* decaf/shake.h */
#define NIF_FUNC_HASH(Id)                                                                                                          \
    {#Id "_hash", 2, libdecaf_nif_##Id##_hash_2, ERL_NIF_NORMAL_JOB_BOUND},                                                        \
    {#Id "_hash_init", 0, libdecaf_nif_##Id##_hash_init_0, ERL_NIF_NORMAL_JOB_BOUND},                                              \
    {#Id "_hash_update", 2, libdecaf_nif_##Id##_hash_update_2, ERL_NIF_NORMAL_JOB_BOUND},                                          \
    {#Id "_hash_final", 2, libdecaf_nif_##Id##_hash_final_2, ERL_NIF_NORMAL_JOB_BOUND}
    NIF_FUNC_HASH(sha2_512),
    NIF_FUNC_HASH(sha3_224),
    NIF_FUNC_HASH(sha3_256),
    NIF_FUNC_HASH(sha3_384),
    NIF_FUNC_HASH(sha3_512),
    NIF_FUNC_HASH(keccak_224),
    NIF_FUNC_HASH(keccak_256),
    NIF_FUNC_HASH(keccak_384),
    NIF_FUNC_HASH(keccak_512),
#undef NIF_FUNC_HASH
#define NIF_FUNC_XOF(Id)                                                                                                          \
    {#Id "_xof", 2, libdecaf_nif_##Id##_xof_2, ERL_NIF_NORMAL_JOB_BOUND},                                                        \
    {#Id "_xof_init", 0, libdecaf_nif_##Id##_xof_init_0, ERL_NIF_NORMAL_JOB_BOUND},                                              \
    {#Id "_xof_update", 2, libdecaf_nif_##Id##_xof_update_2, ERL_NIF_NORMAL_JOB_BOUND},                                          \
    {#Id "_xof_output", 2, libdecaf_nif_##Id##_xof_output_2, ERL_NIF_NORMAL_JOB_BOUND}
    NIF_FUNC_XOF(shake128),
    NIF_FUNC_XOF(shake256),
#undef NIF_FUNC_XOF
    // clang-format on
    /* decaf/spongerng.h */
    {"spongerng_csprng_init_from_buffer", 2, libdecaf_nif_spongerng_csprng_init_from_buffer_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"spongerng_csprng_init_from_file", 3, libdecaf_nif_spongerng_csprng_init_from_file_3, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"spongerng_csprng_init_from_dev_urandom", 0, libdecaf_nif_spongerng_csprng_init_from_dev_urandom_0,
     ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"spongerng_csprng_next", 2, libdecaf_nif_spongerng_csprng_next_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"spongerng_csprng_stir", 2, libdecaf_nif_spongerng_csprng_stir_2, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

static void libdecaf_nif_make_atoms(ErlNifEnv *env);
static int libdecaf_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int libdecaf_nif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void libdecaf_nif_unload(ErlNifEnv *env, void *priv_data);

static void
libdecaf_nif_make_atoms(ErlNifEnv *env)
{
#define ATOM(Id, Value)                                                                                                            \
    {                                                                                                                              \
        libdecaf_nif_atom_table->Id = enif_make_atom(env, Value);                                                                  \
    }
    ATOM(ATOM_badarg, "badarg");
    ATOM(ATOM_error, "error");
    ATOM(ATOM_false, "false");
    ATOM(ATOM_nil, "nil");
    ATOM(ATOM_no_context, "no_context");
    ATOM(ATOM_notsup, "notsup");
    ATOM(ATOM_ok, "ok");
    ATOM(ATOM_sha2_512, "sha2_512");
    ATOM(ATOM_sha3_224, "sha3_224");
    ATOM(ATOM_sha3_256, "sha3_256");
    ATOM(ATOM_sha3_384, "sha3_384");
    ATOM(ATOM_sha3_512, "sha3_512");
    ATOM(ATOM_keccak_224, "keccak_224");
    ATOM(ATOM_keccak_256, "keccak_256");
    ATOM(ATOM_keccak_384, "keccak_384");
    ATOM(ATOM_keccak_512, "keccak_512");
    ATOM(ATOM_shake128, "shake128");
    ATOM(ATOM_shake256, "shake256");
    ATOM(ATOM_true, "true");
    ATOM(ATOM_undefined, "undefined");
#undef ATOM
}

static int
libdecaf_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;
    (void)priv_data;
    (void)load_info;
    /* Load Resource Types */
#define LOAD_RESOURCE_TYPE(Id)                                                                                                     \
    libdecaf_nif_##Id##_resource_type = enif_open_resource_type(env, "libdecaf_nif", #Id, libdecaf_nif_##Id##_dtor,                \
                                                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);                    \
    if (libdecaf_nif_##Id##_resource_type == NULL) {                                                                               \
        retval = -1;                                                                                                               \
        return -1;                                                                                                                 \
    }
    LOAD_RESOURCE_TYPE(trap);
    LOAD_RESOURCE_TYPE(csprng);
    LOAD_RESOURCE_TYPE(hash);
    LOAD_RESOURCE_TYPE(xof);
#undef LOAD_RESOURCE_TYPE
    /* Initialize common atoms */
    (void)libdecaf_nif_make_atoms(env);
    return retval;
}

static int
libdecaf_nif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;
    (void)old_priv_data;
    (void)load_info;
    /* Upgrade Resource Types */
#define UPGRADE_RESOURCE_TYPE(Id)                                                                                                  \
    libdecaf_nif_##Id##_resource_type =                                                                                            \
        enif_open_resource_type(env, "libdecaf_nif", #Id, libdecaf_nif_##Id##_dtor, ERL_NIF_RT_TAKEOVER, NULL);                    \
    if (libdecaf_nif_##Id##_resource_type == NULL) {                                                                               \
        retval = -1;                                                                                                               \
        return -1;                                                                                                                 \
    }
    UPGRADE_RESOURCE_TYPE(trap);
    UPGRADE_RESOURCE_TYPE(csprng);
    UPGRADE_RESOURCE_TYPE(hash);
    UPGRADE_RESOURCE_TYPE(xof);
#undef UPGRADE_RESOURCE_TYPE
    /* Initialize common atoms */
    (void)libdecaf_nif_make_atoms(env);
    return retval;
}

static void
libdecaf_nif_unload(ErlNifEnv *env, void *priv_data)
{
    (void)env;
    (void)priv_data;
    return;
}

ERL_NIF_INIT(libdecaf_nif, libdecaf_nif_funcs, libdecaf_nif_load, NULL, libdecaf_nif_upgrade, libdecaf_nif_unload);
