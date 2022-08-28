// -*- mode: c++; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c++ et

#ifndef XNIF_TRACE_H
#define XNIF_TRACE_H

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <erl_nif.h>

#ifdef __cplusplus
extern "C" {
#endif

// #define XNIF_TRACE 1
#ifdef XNIF_TRACE
#define XNIF_TRACE_C(c)                                                                                                            \
    do {                                                                                                                           \
        putchar(c);                                                                                                                \
        fflush(stdout);                                                                                                            \
    } while (0)
#define XNIF_TRACE_S(s)                                                                                                            \
    do {                                                                                                                           \
        fputs((s), stdout);                                                                                                        \
        fflush(stdout);                                                                                                            \
    } while (0)
#define XNIF_TRACE_F(...)                                                                                                          \
    do {                                                                                                                           \
        enif_fprintf(stderr, "%p ", (void *)enif_thread_self());                                                                   \
        enif_fprintf(stderr, __VA_ARGS__);                                                                                         \
        fflush(stderr);                                                                                                            \
    } while (0)
#else
#define XNIF_TRACE_C(c) ((void)(0))
#define XNIF_TRACE_S(s) ((void)(0))
#define XNIF_TRACE_F(...) ((void)(0))
#endif

static ERL_NIF_TERM xnif_make_string_printf(ErlNifEnv *env, const char *format, ...);
static ERL_NIF_TERM xnif_make_string_vprintf(ErlNifEnv *env, const char *format, va_list ap);

inline ERL_NIF_TERM
xnif_make_string_printf(ErlNifEnv *env, const char *format, ...)
{
    int ret;
    va_list arglist;
    va_start(arglist, format);
    ret = xnif_make_string_vprintf(env, format, arglist);
    va_end(arglist);
    return ret;
}

inline ERL_NIF_TERM
xnif_make_string_vprintf(ErlNifEnv *env, const char *format, va_list ap)
{
#define BUF_SZ 1024
    char buf[BUF_SZ];
    int res;

    buf[0] = '\0';
    res = enif_vsnprintf(buf, BUF_SZ, format, ap);
    if (res < 0) {
        return enif_raise_exception(env, enif_make_string(env, "Call to xnif_make_string_vprintf() failed", ERL_NIF_LATIN1));
    }
    if (res < BUF_SZ) {
        return enif_make_string_len(env, buf, (size_t)res, ERL_NIF_LATIN1);
    }
    return enif_make_string_len(env, buf, BUF_SZ, ERL_NIF_LATIN1);
#undef BUF_SZ
}

#ifdef __cplusplus
}
#endif

#endif
