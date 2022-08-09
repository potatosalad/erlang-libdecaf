// -*- mode: c++; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c++ et

#ifndef LIBDECAF_NIF_H
#define LIBDECAF_NIF_H

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <erl_nif.h>

#include "xnif_trace.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Resource Types and Traps */

typedef struct libdecaf_nif_trap_s libdecaf_nif_trap_t;
typedef enum libdecaf_nif_trap_type_t libdecaf_nif_trap_type_t;

enum libdecaf_nif_trap_type_t {
    LIBDECAF_NIF_TRAP_TYPE_CSPRNG_NEXT,
    LIBDECAF_NIF_TRAP_TYPE_CSPRNG_STIR,
    LIBDECAF_NIF_TRAP_TYPE_HASH,
    LIBDECAF_NIF_TRAP_TYPE_HASH_UPDATE,
    LIBDECAF_NIF_TRAP_TYPE_XOF_ABSORB,
    LIBDECAF_NIF_TRAP_TYPE_XOF_SQUEEZE,
    LIBDECAF_NIF_TRAP_TYPE_XOF_UPDATE,
    LIBDECAF_NIF_TRAP_TYPE_XOF_OUTPUT,
};

struct libdecaf_nif_trap_s {
    libdecaf_nif_trap_type_t type;
    void (*dtor)(ErlNifEnv *caller_env, void *obj);
    ErlNifEnv *work_env;
};

extern ErlNifResourceType *libdecaf_nif_trap_resource_type;
extern ErlNifResourceType *libdecaf_nif_csprng_resource_type;
extern ErlNifResourceType *libdecaf_nif_hash_resource_type;
extern ErlNifResourceType *libdecaf_nif_xof_resource_type;

/* Atom Table */

typedef struct libdecaf_nif_atom_table_s libdecaf_nif_atom_table_t;

struct libdecaf_nif_atom_table_s {
    ERL_NIF_TERM ATOM_badarg;
    ERL_NIF_TERM ATOM_error;
    ERL_NIF_TERM ATOM_false;
    ERL_NIF_TERM ATOM_nil;
    ERL_NIF_TERM ATOM_no_context;
    ERL_NIF_TERM ATOM_notsup;
    ERL_NIF_TERM ATOM_ok;
    ERL_NIF_TERM ATOM_sha2_512;
    ERL_NIF_TERM ATOM_sha3_224;
    ERL_NIF_TERM ATOM_sha3_256;
    ERL_NIF_TERM ATOM_sha3_384;
    ERL_NIF_TERM ATOM_sha3_512;
    ERL_NIF_TERM ATOM_keccak_224;
    ERL_NIF_TERM ATOM_keccak_256;
    ERL_NIF_TERM ATOM_keccak_384;
    ERL_NIF_TERM ATOM_keccak_512;
    ERL_NIF_TERM ATOM_shake128;
    ERL_NIF_TERM ATOM_shake256;
    ERL_NIF_TERM ATOM_true;
    ERL_NIF_TERM ATOM_undefined;
};

extern libdecaf_nif_atom_table_t *libdecaf_nif_atom_table;

/* NIF Utility Macros */

#define ERL_NIF_NORMAL_JOB_BOUND (0)

#define REDUCTIONS_UNTIL_YCF_YIELD() (20000)
#define BUMP_ALL_REDS(env)                                                                                                         \
    do {                                                                                                                           \
        (void)enif_consume_timeslice((env), 100);                                                                                  \
    } while (0)
#define BUMP_REMAINING_REDS(env, nr_of_reductions)                                                                                 \
    do {                                                                                                                           \
        (void)enif_consume_timeslice((env),                                                                                        \
                                     (int)((REDUCTIONS_UNTIL_YCF_YIELD() - (nr_of_reductions)) / REDUCTIONS_UNTIL_YCF_YIELD()));   \
    } while (0)

/* All nif functions return a valid value or throws an exception */
#define EXCP(Env, Id, Str)                                                                                                         \
    enif_raise_exception((Env), enif_make_tuple3((Env), (Id),                                                                      \
                                                 enif_make_tuple2((Env), enif_make_string((Env), __FILE__, (ERL_NIF_LATIN1)),      \
                                                                  enif_make_int((Env), __LINE__)),                                 \
                                                 enif_make_string((Env), (Str), (ERL_NIF_LATIN1))))

#define EXCP_NOTSUP(Env, Str) EXCP((Env), libdecaf_nif_atom_table->ATOM_notsup, (Str))
#define EXCP_BADARG(Env, Str) EXCP((Env), libdecaf_nif_atom_table->ATOM_badarg, (Str))
#define EXCP_ERROR(Env, Str) EXCP((Env), libdecaf_nif_atom_table->ATOM_error, (Str))

#ifdef __cplusplus
}
#endif

#endif
