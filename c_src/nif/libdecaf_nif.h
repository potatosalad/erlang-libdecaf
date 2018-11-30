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

/* Global Types */

typedef struct libdecaf_nif_priv_data_20181127_s libdecaf_nif_priv_data_20181127_t;

struct libdecaf_nif_priv_data_20181127_s {
    uint32_t version;
    ErlNifResourceType *sha2_512_ctx;
    ErlNifResourceType *sha3_224_ctx;
    ErlNifResourceType *sha3_256_ctx;
    ErlNifResourceType *sha3_384_ctx;
    ErlNifResourceType *sha3_512_ctx;
    ErlNifResourceType *shake128_ctx;
    ErlNifResourceType *shake256_ctx;
    ErlNifResourceType *spongerng_ctx;
};

#define libdecaf_nif_priv_data_t libdecaf_nif_priv_data_20181127_t
#define libdecaf_nif_priv_data_version 20181127

#ifdef __cplusplus
}
#endif

#endif
