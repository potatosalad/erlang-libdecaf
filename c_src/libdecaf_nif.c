// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libdecaf_nif.h"

/*
 * Erlang NIF functions
 */

/* decaf/decaf_255.h */
#include "decaf_255_funcs.h"
/* decaf/decaf_448.h */
#include "decaf_448_funcs.h"
/* decaf/eddsa_255.h */
#include "eddsa_255_funcs.h"
/* decaf/eddsa_448.h */
#include "eddsa_448_funcs.h"
/* decaf/sha512.h */
#include "sha512_funcs.h"
/* decaf/shake.h */
#include "shake_funcs.h"

/*
 * Erlang NIF callbacks
 */
static int
libdecaf_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	/* Allocate private data */
	libdecaf_priv_data_t *data = enif_alloc(sizeof(libdecaf_priv_data_t));
	if (data == NULL) {
		return 1;
	}

	/* Initialize common atoms */
	#define ATOM(Id, Value) { Id = enif_make_atom(env, Value); }
		ATOM(ATOM_error, "error");
		ATOM(ATOM_false, "false");
		ATOM(ATOM_true, "true");
		ATOM(ATOM_sha2_512, "sha2_512");
		ATOM(ATOM_sha3_224, "sha3_224");
		ATOM(ATOM_sha3_256, "sha3_256");
		ATOM(ATOM_sha3_384, "sha3_384");
		ATOM(ATOM_sha3_512, "sha3_512");
		ATOM(ATOM_shake128, "shake128");
		ATOM(ATOM_shake256, "shake256");
	#undef ATOM

	data->version = libdecaf_priv_data_version;
	data->keccak_sponge = enif_open_resource_type(env, NULL, "libdecaf_keccak_sponge", NULL, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
	data->sha2_512_ctx = enif_open_resource_type(env, NULL, "libdecaf_sha2_512_ctx", NULL, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);

	*priv_data = (void *)(data);

	return 0;
}

static int
libdecaf_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
	return libdecaf_nif_load(env, priv_data, load_info);
}

static void
libdecaf_nif_unload(ErlNifEnv *env, void *priv_data)
{
	(void) enif_free(priv_data);
	return;
}

ERL_NIF_INIT(libdecaf, libdecaf_nif_funcs, libdecaf_nif_load, NULL, libdecaf_nif_upgrade, libdecaf_nif_unload);
