#ifndef LIBDECAF_NIF_GROUPS_H
#define LIBDECAF_NIF_GROUPS_H
#include "libdecaf_nif.h"

int libdecaf_nif_groups_load(ErlNifEnv *env);

#define LIBDECAF_GROUP_DECL(Name)                                                                                                  \
    ERL_NIF_TERM libdecaf_nif_##Name##_identity_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                            \
    ERL_NIF_TERM libdecaf_nif_##Name##_base_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                                \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_is_valid_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                      \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_eq_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                            \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_add_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                           \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_sub_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                           \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_negate_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                        \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_double_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                        \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_scalarmul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                     \
    ERL_NIF_TERM libdecaf_nif_##Name##_base_scalarmul_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                      \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_double_scalarmul_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);              \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_from_hash_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                     \
    ERL_NIF_TERM libdecaf_nif_##Name##_point_from_hash_nonuniform_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);          \
    ERL_NIF_TERM libdecaf_nif_##Name##_precompute_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                          \
    ERL_NIF_TERM libdecaf_nif_##Name##_precomputed_scalarmul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);               \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_is_canonical_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                 \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_reduce_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                       \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_add_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                          \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_sub_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                          \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_mul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                          \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_negate_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                       \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_halve_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                        \
    ERL_NIF_TERM libdecaf_nif_##Name##_scalar_invert_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

LIBDECAF_GROUP_DECL(ristretto255)
LIBDECAF_GROUP_DECL(decaf448)
#undef LIBDECAF_GROUP_DECL

#define LIBDECAF_GROUP_NIFS(Name)                                                                                                  \
    {#Name "_identity", 0, libdecaf_nif_##Name##_identity_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                         \
        {#Name "_base", 0, libdecaf_nif_##Name##_base_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                             \
        {#Name "_point_is_valid", 1, libdecaf_nif_##Name##_point_is_valid_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                         \
        {#Name "_point_eq", 2, libdecaf_nif_##Name##_point_eq_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                     \
        {#Name "_point_add", 2, libdecaf_nif_##Name##_point_add_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                   \
        {#Name "_point_sub", 2, libdecaf_nif_##Name##_point_sub_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                   \
        {#Name "_point_negate", 1, libdecaf_nif_##Name##_point_negate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                             \
        {#Name "_point_double", 1, libdecaf_nif_##Name##_point_double_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                             \
        {#Name "_point_scalarmul", 2, libdecaf_nif_##Name##_point_scalarmul_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},                       \
        {#Name "_base_scalarmul", 1, libdecaf_nif_##Name##_base_scalarmul_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                         \
        {#Name "_point_double_scalarmul", 4, libdecaf_nif_##Name##_point_double_scalarmul_4, ERL_NIF_DIRTY_JOB_CPU_BOUND},         \
        {#Name "_point_from_hash", 1, libdecaf_nif_##Name##_point_from_hash_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                       \
        {#Name "_point_from_hash_nonuniform", 1, libdecaf_nif_##Name##_point_from_hash_nonuniform_1, ERL_NIF_DIRTY_JOB_CPU_BOUND}, \
        {#Name "_precompute", 1, libdecaf_nif_##Name##_precompute_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                 \
        {#Name "_precomputed_scalarmul", 2, libdecaf_nif_##Name##_precomputed_scalarmul_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},           \
        {#Name "_scalar_is_canonical", 1, libdecaf_nif_##Name##_scalar_is_canonical_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},               \
        {#Name "_scalar_reduce", 1, libdecaf_nif_##Name##_scalar_reduce_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                           \
        {#Name "_scalar_add", 2, libdecaf_nif_##Name##_scalar_add_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                 \
        {#Name "_scalar_sub", 2, libdecaf_nif_##Name##_scalar_sub_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                 \
        {#Name "_scalar_mul", 2, libdecaf_nif_##Name##_scalar_mul_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},                                 \
        {#Name "_scalar_negate", 1, libdecaf_nif_##Name##_scalar_negate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                           \
        {#Name "_scalar_halve", 1, libdecaf_nif_##Name##_scalar_halve_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},                             \
    {                                                                                                                              \
        #Name "_scalar_invert", 1, libdecaf_nif_##Name##_scalar_invert_1, ERL_NIF_DIRTY_JOB_CPU_BOUND                              \
    }

#endif
