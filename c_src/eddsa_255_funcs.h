// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include <decaf/eddsa_255.h>

/*
 * Erlang NIF functions
 */

/* decaf/eddsa_255.h */

static ERL_NIF_TERM
libdecaf_decaf_255_eddsa_derive_public_key_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary privkey;

	if (argc != 1 || !enif_inspect_binary(env, argv[0], &privkey)
			|| privkey.size != DECAF_255_EDDSA_PRIVATE_BYTES) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *pubkey = (uint8_t *)(enif_make_new_binary(env, DECAF_255_EDDSA_PUBLIC_BYTES, &out));

	(void) decaf_255_eddsa_derive_public_key(pubkey, privkey.data);

	return out;
}

static ERL_NIF_TERM
libdecaf_decaf_255_eddsa_sign_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary privkey;
	ErlNifBinary pubkey;
	ErlNifBinary message;
	unsigned int prehashed;

	if (argc != 4 || !enif_inspect_binary(env, argv[0], &privkey)
			|| privkey.size != DECAF_255_EDDSA_PRIVATE_BYTES
			|| !enif_inspect_binary(env, argv[1], &pubkey)
			|| pubkey.size != DECAF_255_EDDSA_PUBLIC_BYTES
			|| !enif_inspect_binary(env, argv[2], &message)
			|| !enif_get_uint(env, argv[3], &prehashed)
			|| (prehashed != 0 && prehashed != 1)) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *signature = (uint8_t *)(enif_make_new_binary(env, DECAF_255_EDDSA_SIGNATURE_BYTES, &out));

	(void) decaf_255_eddsa_sign(signature, privkey.data, pubkey.data, message.data, message.size, prehashed);

	return out;
}

static ERL_NIF_TERM
libdecaf_decaf_255_eddsa_verify_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary signature;
	ErlNifBinary pubkey;
	ErlNifBinary message;
	unsigned int prehashed;

	if (argc != 4 || !enif_inspect_binary(env, argv[0], &signature)
			|| signature.size != DECAF_255_EDDSA_SIGNATURE_BYTES
			|| !enif_inspect_binary(env, argv[1], &pubkey)
			|| pubkey.size != DECAF_255_EDDSA_PUBLIC_BYTES
			|| !enif_inspect_binary(env, argv[2], &message)
			|| !enif_get_uint(env, argv[3], &prehashed)
			|| (prehashed != 0 && prehashed != 1)) {
		return enif_make_badarg(env);
	}

	if (decaf_255_eddsa_verify(signature.data, pubkey.data, message.data, message.size, prehashed) == DECAF_SUCCESS) {
		return ATOM_true;
	} else {
		return ATOM_false;
	}
}
