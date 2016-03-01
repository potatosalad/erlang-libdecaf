// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include <decaf/decaf_448.h>

/*
 * Erlang NIF functions
 */

/* decaf/decaf_448.h */

static ERL_NIF_TERM
libdecaf_decaf_x448_base_scalarmul_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary scalar;

	if (argc != 1 || !enif_inspect_binary(env, argv[0], &scalar)
			|| scalar.size != X448_PRIVATE_BYTES) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *u = (uint8_t *)(enif_make_new_binary(env, X448_PUBLIC_BYTES, &out));

	(void) decaf_x448_base_scalarmul(u, scalar.data);

	return out;
}

static ERL_NIF_TERM
libdecaf_decaf_x448_direct_scalarmul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary base;
	ErlNifBinary scalar;

	if (argc != 2 || !enif_inspect_binary(env, argv[0], &base)
			|| base.size != X448_PUBLIC_BYTES
			|| !enif_inspect_binary(env, argv[1], &scalar)
			|| scalar.size != X448_PRIVATE_BYTES) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *u = (uint8_t *)(enif_make_new_binary(env, X448_PUBLIC_BYTES, &out));

	if (decaf_x448_direct_scalarmul(u, base.data, scalar.data) == DECAF_SUCCESS) {
		return out;
	} else {
		return ATOM_error;
	}
}
