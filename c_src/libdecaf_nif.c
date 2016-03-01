// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libdecaf_nif.h"
#include <decaf/crypto.h>
#include <decaf/eddsa_255.h>
#include <decaf/eddsa_448.h>

/*
 * Erlang NIF functions
 */

/* decaf/decaf_255.h */

static ERL_NIF_TERM
libdecaf_decaf_x25519_base_scalarmul_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary scalar;

	if (argc != 1 || !enif_inspect_binary(env, argv[0], &scalar)
			|| scalar.size != X25519_PRIVATE_BYTES) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *u = (uint8_t *)(enif_make_new_binary(env, X25519_PUBLIC_BYTES, &out));

	(void) decaf_x25519_base_scalarmul(u, scalar.data);

	return out;
}

static ERL_NIF_TERM
libdecaf_decaf_x25519_direct_scalarmul_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary base;
	ErlNifBinary scalar;

	if (argc != 2 || !enif_inspect_binary(env, argv[0], &base)
			|| base.size != X25519_PUBLIC_BYTES
			|| !enif_inspect_binary(env, argv[1], &scalar)
			|| scalar.size != X25519_PRIVATE_BYTES) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM out;
	uint8_t *u = (uint8_t *)(enif_make_new_binary(env, X25519_PUBLIC_BYTES, &out));

	if (decaf_x25519_direct_scalarmul(u, base.data, scalar.data) == DECAF_SUCCESS) {
		return out;
	} else {
		return ATOM_error;
	}
}

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
