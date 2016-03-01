// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include <decaf/eddsa_448.h>

/*
 * Erlang NIF functions
 */

/* decaf/eddsa_448.h */

static ERL_NIF_TERM
libdecaf_decaf_448_eddsa_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary privkey;

	if (argc != 1 || !enif_inspect_binary(env, argv[0], &privkey)
			|| (privkey.size != DECAF_448_EDDSA_PRIVATE_BYTES && privkey.size != 32)) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *pubkey = (uint8_t *)(enif_make_new_binary(env, DECAF_448_EDDSA_PUBLIC_BYTES, &out));

	(void) decaf_448_eddsa_derive_public_key(pubkey, privkey.data, (privkey.size == 32) ? 1 : 0);

	return out;
}

static ERL_NIF_TERM
libdecaf_decaf_448_eddsa_sign_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary privkey;
	ErlNifBinary pubkey;
	ErlNifBinary message;
	unsigned int prehashed;
	ErlNifBinary context;

	if (argc != 5 || !enif_inspect_binary(env, argv[0], &privkey)
			|| (privkey.size != DECAF_448_EDDSA_PRIVATE_BYTES && privkey.size != 32)
			|| !enif_inspect_binary(env, argv[1], &pubkey)
			|| pubkey.size != DECAF_448_EDDSA_PUBLIC_BYTES
			|| !enif_inspect_binary(env, argv[2], &message)
			|| !enif_get_uint(env, argv[3], &prehashed)
			|| (prehashed != 0 && prehashed != 1)
			|| !enif_inspect_binary(env, argv[4], &context)
			|| context.size > 255) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *signature = (uint8_t *)(enif_make_new_binary(env, DECAF_448_EDDSA_SIGNATURE_BYTES, &out));

	(void) decaf_448_eddsa_sign(signature, privkey.data, pubkey.data, message.data, message.size, prehashed, context.data, context.size, (privkey.size == 32) ? 1 : 0);

	return out;
}

static ERL_NIF_TERM
libdecaf_decaf_448_eddsa_verify_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary signature;
	ErlNifBinary pubkey;
	ErlNifBinary message;
	unsigned int prehashed;
	ErlNifBinary context;

	if (argc != 5 || !enif_inspect_binary(env, argv[0], &signature)
			|| signature.size != DECAF_448_EDDSA_SIGNATURE_BYTES
			|| !enif_inspect_binary(env, argv[1], &pubkey)
			|| pubkey.size != DECAF_448_EDDSA_PUBLIC_BYTES
			|| !enif_inspect_binary(env, argv[2], &message)
			|| !enif_get_uint(env, argv[3], &prehashed)
			|| (prehashed != 0 && prehashed != 1)
			|| !enif_inspect_binary(env, argv[4], &context)
			|| context.size > 255) {
		return enif_make_badarg(env);
	}

	if (decaf_448_eddsa_verify(signature.data, pubkey.data, message.data, message.size, prehashed, context.data, context.size) == DECAF_SUCCESS) {
		return ATOM_true;
	} else {
		return ATOM_false;
	}
}
