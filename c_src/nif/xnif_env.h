// -*- mode: c++; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c++ et

#ifndef XNIF_ENV_H
#define XNIF_ENV_H

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <erl_nif.h>

#include "xnif_slice.h"
#include "xnif_trace.h"

/* Global Types */

#define XNIF_FEATURE_NONE 0x00
#define XNIF_FEATURE_SLICE 0x01

typedef struct xnif_env_config_s xnif_env_config_t;
typedef int xnif_env_load_t(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
typedef int xnif_env_upgrade_t(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
typedef void xnif_env_unload_t(ErlNifEnv *env, void *priv_data);

struct xnif_env_config_s {
    int flag;
    xnif_env_load_t *load;
    xnif_env_upgrade_t *upgrade;
    xnif_env_unload_t *unload;
};

typedef struct xnif_env_s xnif_env_t;

struct xnif_env_s {
    uint32_t version;
    xnif_env_config_t config;
    void *data;
};

typedef struct xnif_env_priv_data_20181127_s xnif_env_priv_data_20181127_t;

struct xnif_env_priv_data_20181127_s {
    xnif_env_t super;
    void *xnif_slice_data;
};

#define xnif_env_priv_data_t xnif_env_priv_data_20181127_t
#define xnif_env_priv_data_version 20181127

#ifdef __cplusplus
extern "C" {
#endif

/* Public Functions */

static xnif_env_t *xnif_env_get(ErlNifEnv *env);
static void *xnif_env_priv_data(ErlNifEnv *env);
static int xnif_env_load(ErlNifEnv *env, xnif_env_t **xenvp, ERL_NIF_TERM load_info, const xnif_env_config_t *config);
static int xnif_env_upgrade(ErlNifEnv *env, xnif_env_t **new_xenvp, xnif_env_t **old_xenvp, ERL_NIF_TERM load_info,
                            const xnif_env_config_t *new_config);
static void xnif_env_unload(ErlNifEnv *env, xnif_env_t *xenv);

inline xnif_env_t *
xnif_env_get(ErlNifEnv *env)
{
    xnif_env_t *priv_data = NULL;
    priv_data = (void *)enif_priv_data(env);
    if (priv_data == NULL) {
        return NULL;
    }
    if (priv_data->version != xnif_env_priv_data_version) {
        return NULL;
    }
    return priv_data;
}

inline void *
xnif_env_priv_data(ErlNifEnv *env)
{
    xnif_env_t *priv_data = NULL;
    priv_data = xnif_env_get(env);
    if (priv_data == NULL) {
        return NULL;
    }
    return priv_data->data;
}

inline int
xnif_env_load(ErlNifEnv *env, xnif_env_t **xenvp, ERL_NIF_TERM load_info, const xnif_env_config_t *config)
{
    int retval = 0;
    xnif_env_priv_data_t *xpriv = NULL;
    if (env == NULL || config == NULL) {
        return -1;
    }
    xpriv = (void *)enif_alloc(sizeof(xnif_env_priv_data_t));
    if (xpriv == NULL) {
        return -1;
    }
    xpriv->super.version = xnif_env_priv_data_version;
    xpriv->super.config = *config;
    xpriv->super.data = NULL;
    xpriv->xnif_slice_data = NULL;
    if ((xpriv->super.config.flag & XNIF_FEATURE_SLICE) != 0) {
        retval = xnif_slice_load(env, &(xpriv->xnif_slice_data), load_info);
        if (retval != 0) {
            (void)enif_free((void *)xpriv);
            return -1;
        }
    }
    if (xpriv->super.config.load != NULL && (retval = xpriv->super.config.load(env, &(xpriv->super.data), load_info)) != 0) {
        (void)enif_free((void *)xpriv);
        return retval;
    }
    *xenvp = &xpriv->super;
    return retval;
}

inline int
xnif_env_upgrade(ErlNifEnv *env, xnif_env_t **new_xenvp, xnif_env_t **old_xenvp, ERL_NIF_TERM load_info,
                 const xnif_env_config_t *new_config)
{
    int retval = 0;
    xnif_env_priv_data_t *old_xpriv = (void *)*old_xenvp;
    xnif_env_priv_data_t *new_xpriv = NULL;
    if (env == NULL || new_config == NULL) {
        return -1;
    }
    if (old_xpriv == NULL) {
        return xnif_env_load(env, new_xenvp, load_info, new_config);
    }
    new_xpriv = (void *)enif_alloc(sizeof(xnif_env_priv_data_t));
    if (new_xpriv == NULL) {
        return -1;
    }
    new_xpriv->super.version = xnif_env_priv_data_version;
    new_xpriv->super.config = *new_config;
    new_xpriv->super.data = NULL;
    new_xpriv->xnif_slice_data = NULL;
    if (old_xpriv->super.version == 20181127) {
        if ((new_xpriv->super.config.flag & XNIF_FEATURE_SLICE) != 0) {
            retval = xnif_slice_upgrade(env, &(new_xpriv->xnif_slice_data), &(old_xpriv->xnif_slice_data), load_info);
            if (retval != 0) {
                (void)enif_free((void *)new_xpriv);
                return retval;
            }
        }
        if (old_xpriv->super.config.upgrade != NULL) {
            retval = old_xpriv->super.config.upgrade(env, &(new_xpriv->super.data), &(old_xpriv->super.data), load_info);
            if (retval != 0) {
                (void)enif_free((void *)new_xpriv);
                return retval;
            }
        }
    } else {
        return -1;
    }
    *new_xenvp = &new_xpriv->super;
    return retval;
}

inline void
xnif_env_unload(ErlNifEnv *env, xnif_env_t *xenv)
{
    if (xenv->version == 20181127) {
        xnif_env_priv_data_20181127_t *xpriv = (void *)xenv;
        if (xpriv->super.config.unload != NULL) {
            (void)xpriv->super.config.unload(env, &(xpriv->super.data));
            xpriv->super.data = NULL;
        }
        if ((xpriv->super.config.flag & XNIF_FEATURE_SLICE) != 0) {
            (void)xnif_slice_unload(env, xpriv->xnif_slice_data);
            xpriv->xnif_slice_data = NULL;
        }
        (void)enif_free((void *)xpriv);
    }
    return;
}

#ifdef __cplusplus
}
#endif

#endif
