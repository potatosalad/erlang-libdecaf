// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include <decaf/point_255.h>

/*
 * Erlang NIF functions
 */

/* decaf/point_255.h */

static ERL_NIF_TERM
libdecaf_x25519_generate_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary scalar;

	if (argc != 1 || !enif_inspect_binary(env, argv[0], &scalar)
			|| scalar.size != DECAF_X25519_PRIVATE_BYTES) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *u = (uint8_t *)(enif_make_new_binary(env, DECAF_X25519_PUBLIC_BYTES, &out));

	(void) decaf_x25519_generate_key(u, scalar.data);

	return out;
}

static ERL_NIF_TERM
libdecaf_x25519_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary base;
	ErlNifBinary scalar;

	if (argc != 2 || !enif_inspect_binary(env, argv[0], &base)
			|| base.size != DECAF_X25519_PUBLIC_BYTES
			|| !enif_inspect_binary(env, argv[1], &scalar)
			|| scalar.size != DECAF_X25519_PRIVATE_BYTES) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *u = (uint8_t *)(enif_make_new_binary(env, DECAF_X25519_PUBLIC_BYTES, &out));

	if (decaf_x25519(u, base.data, scalar.data) == DECAF_SUCCESS) {
		return out;
	} else {
		return ATOM_error;
	}
}
