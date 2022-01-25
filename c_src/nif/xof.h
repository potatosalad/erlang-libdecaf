// -*- mode: c++; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c++ et

#ifndef LIBDECAF_NIF_XOF_H
#define LIBDECAF_NIF_XOF_H

#include "libdecaf_nif.h"

#include <decaf/shake.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libdecaf_nif_xof_table_s libdecaf_nif_xof_table_t;
typedef struct libdecaf_nif_xof_s libdecaf_nif_xof_t;
typedef enum libdecaf_nif_xof_type_t libdecaf_nif_xof_type_t;
typedef struct libdecaf_nif_xof_ctx_s libdecaf_nif_xof_ctx_t;

enum libdecaf_nif_xof_type_t {
    LIBDECAF_NIF_XOF_TYPE_SHAKE128,
    LIBDECAF_NIF_XOF_TYPE_SHAKE256,
};

struct libdecaf_nif_xof_s {
    libdecaf_nif_xof_type_t type;
    void (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *input, size_t input_len);
    void (*output)(void *ctx, uint8_t *output, size_t output_len);
    void (*destroy)(void *ctx);
};

struct libdecaf_nif_xof_ctx_s {
    union {
        struct decaf_shake128_ctx_s shake128;
        struct decaf_shake256_ctx_s shake256;
    } u;
    libdecaf_nif_xof_type_t type;
    bool squeezing;
};

struct libdecaf_nif_xof_table_s {
    libdecaf_nif_xof_t shake128;
    libdecaf_nif_xof_t shake256;
};

extern libdecaf_nif_xof_table_t *libdecaf_nif_xof_table;

extern ERL_NIF_TERM libdecaf_nif_xof_2(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_xof_init_0(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_xof_update_2(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_xof_output_2(libdecaf_nif_xof_t *xof, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

static libdecaf_nif_xof_t *libdecaf_nif_xof_from_type(libdecaf_nif_xof_type_t type);

inline libdecaf_nif_xof_t *
libdecaf_nif_xof_from_type(libdecaf_nif_xof_type_t type)
{
    libdecaf_nif_xof_t *xof = NULL;
    switch (type) {
    case LIBDECAF_NIF_XOF_TYPE_SHAKE128:
        xof = &libdecaf_nif_xof_table->shake128;
        break;
    case LIBDECAF_NIF_XOF_TYPE_SHAKE256:
        xof = &libdecaf_nif_xof_table->shake256;
        break;
    default:
        break;
    }
    return xof;
}

#ifdef __cplusplus
}
#endif

#endif
