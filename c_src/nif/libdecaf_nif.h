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

#include "libdecaf_nif_atoms.h"

/* Resource Types */

extern ErlNifResourceType *libdecaf_nif_csprng_resource_type;
extern ErlNifResourceType *libdecaf_nif_ed25519_keypair_resource_type;
extern ErlNifResourceType *libdecaf_nif_ed448_keypair_resource_type;

/* NIF Utility Macros and Functions */

#ifndef ERL_NIF_NORMAL_JOB_BOUND
#define ERL_NIF_NORMAL_JOB_BOUND (0)
#endif

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

#define EXCP_F(Env, Id, Fmt, ...)                                                                                                  \
    enif_raise_exception((Env), enif_make_tuple3((Env), (Id),                                                                      \
                                                 enif_make_tuple2((Env), enif_make_string((Env), __FILE__, (ERL_NIF_LATIN1)),      \
                                                                  enif_make_int((Env), __LINE__)),                                 \
                                                 xnif_make_string_printf((Env), (Fmt), __VA_ARGS__)))

#define EXCP_NOTSUP(Env, Str) EXCP((Env), ATOM(notsup), (Str))
#define EXCP_BADARG(Env, Str) EXCP((Env), ATOM(badarg), (Str))
#define EXCP_BADARG_F(Env, Fmt, ...) EXCP_F((Env), ATOM(badarg), Fmt, __VA_ARGS__)
#define EXCP_ERROR(Env, Str) EXCP((Env), ATOM(error), (Str))
#define EXCP_ERROR_F(Env, Fmt, ...) EXCP_F((Env), ATOM(error), Fmt, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
