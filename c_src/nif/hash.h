// -*- mode: c++; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c++ et

#ifndef LIBDECAF_NIF_HASH_H
#define LIBDECAF_NIF_HASH_H

#include "libdecaf_nif.h"

#include <decaf/sha512.h>
#include <decaf/shake.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libdecaf_nif_hash_table_s libdecaf_nif_hash_table_t;
typedef struct libdecaf_nif_hash_s libdecaf_nif_hash_t;
typedef enum libdecaf_nif_hash_type_t libdecaf_nif_hash_type_t;
typedef struct libdecaf_nif_hash_ctx_s libdecaf_nif_hash_ctx_t;

enum libdecaf_nif_hash_type_t {
    LIBDECAF_NIF_HASH_TYPE_SHA2_512,
    LIBDECAF_NIF_HASH_TYPE_SHA3_224,
    LIBDECAF_NIF_HASH_TYPE_SHA3_256,
    LIBDECAF_NIF_HASH_TYPE_SHA3_384,
    LIBDECAF_NIF_HASH_TYPE_SHA3_512,
    LIBDECAF_NIF_HASH_TYPE_KECCAK_224,
    LIBDECAF_NIF_HASH_TYPE_KECCAK_256,
    LIBDECAF_NIF_HASH_TYPE_KECCAK_384,
    LIBDECAF_NIF_HASH_TYPE_KECCAK_512,
};

struct libdecaf_nif_hash_s {
    libdecaf_nif_hash_type_t type;
    size_t max_output_len;
    void (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *input, size_t input_len);
    void (*final)(void *ctx, uint8_t *output, size_t output_len);
    void (*destroy)(void *ctx);
};

struct libdecaf_nif_hash_ctx_s {
    union {
        struct decaf_sha512_ctx_s sha2_512;
        struct decaf_sha3_224_ctx_s sha3_224;
        struct decaf_sha3_256_ctx_s sha3_256;
        struct decaf_sha3_384_ctx_s sha3_384;
        struct decaf_sha3_512_ctx_s sha3_512;
        struct decaf_keccak_224_ctx_s keccak_224;
        struct decaf_keccak_256_ctx_s keccak_256;
        struct decaf_keccak_384_ctx_s keccak_384;
        struct decaf_keccak_512_ctx_s keccak_512;
    } u;
    libdecaf_nif_hash_type_t type;
};

struct libdecaf_nif_hash_table_s {
    libdecaf_nif_hash_t sha2_512;
    libdecaf_nif_hash_t sha3_224;
    libdecaf_nif_hash_t sha3_256;
    libdecaf_nif_hash_t sha3_384;
    libdecaf_nif_hash_t sha3_512;
    libdecaf_nif_hash_t keccak_224;
    libdecaf_nif_hash_t keccak_256;
    libdecaf_nif_hash_t keccak_384;
    libdecaf_nif_hash_t keccak_512;
};

extern libdecaf_nif_hash_table_t *libdecaf_nif_hash_table;

extern ERL_NIF_TERM libdecaf_nif_hash_2(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_hash_init_0(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_hash_update_2(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM libdecaf_nif_hash_final_2(libdecaf_nif_hash_t *hash, ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

static libdecaf_nif_hash_t *libdecaf_nif_hash_from_type(libdecaf_nif_hash_type_t type);

inline libdecaf_nif_hash_t *
libdecaf_nif_hash_from_type(libdecaf_nif_hash_type_t type)
{
    libdecaf_nif_hash_t *hash = NULL;
    switch (type) {
    case LIBDECAF_NIF_HASH_TYPE_SHA2_512:
        hash = &libdecaf_nif_hash_table->sha2_512;
        break;
    case LIBDECAF_NIF_HASH_TYPE_SHA3_224:
        hash = &libdecaf_nif_hash_table->sha3_224;
        break;
    case LIBDECAF_NIF_HASH_TYPE_SHA3_256:
        hash = &libdecaf_nif_hash_table->sha3_256;
        break;
    case LIBDECAF_NIF_HASH_TYPE_SHA3_384:
        hash = &libdecaf_nif_hash_table->sha3_384;
        break;
    case LIBDECAF_NIF_HASH_TYPE_SHA3_512:
        hash = &libdecaf_nif_hash_table->sha3_512;
        break;
    case LIBDECAF_NIF_HASH_TYPE_KECCAK_224:
        hash = &libdecaf_nif_hash_table->keccak_224;
        break;
    case LIBDECAF_NIF_HASH_TYPE_KECCAK_256:
        hash = &libdecaf_nif_hash_table->keccak_256;
        break;
    case LIBDECAF_NIF_HASH_TYPE_KECCAK_384:
        hash = &libdecaf_nif_hash_table->keccak_384;
        break;
    case LIBDECAF_NIF_HASH_TYPE_KECCAK_512:
        hash = &libdecaf_nif_hash_table->keccak_512;
        break;
    default:
        break;
    }
    return hash;
}

#ifdef __cplusplus
}
#endif

#endif
