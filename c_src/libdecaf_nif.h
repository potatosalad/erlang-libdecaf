// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef LIBDECAF_NIF_H
#define LIBDECAF_NIF_H

#include <sys/types.h>
#include <sys/time.h>
#include <erl_nif.h>
#include <string.h>
#include <stdio.h>

#ifndef timersub
#define	timersub(tvp, uvp, vvp)					\
	do								\
	{								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0)					\
		{							\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while ((vvp)->tv_usec >= 1000000)
#endif

#define MAX_PER_SLICE	20000	// 20 KB

ERL_NIF_TERM	ATOM_error;
ERL_NIF_TERM	ATOM_false;
ERL_NIF_TERM	ATOM_true;
ERL_NIF_TERM	ATOM_sha2_512;
ERL_NIF_TERM	ATOM_sha3_224;
ERL_NIF_TERM	ATOM_sha3_256;
ERL_NIF_TERM	ATOM_sha3_384;
ERL_NIF_TERM	ATOM_sha3_512;
ERL_NIF_TERM	ATOM_shake128;
ERL_NIF_TERM	ATOM_shake256;

/*
 * Erlang NIF functions
 */

#define NIF_FUN(function, arity)	\
	static ERL_NIF_TERM	libdecaf_ ##function## _ ##arity (ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])

/* decaf/decaf_255.h */
NIF_FUN(decaf_x25519_base_scalarmul,		1);
NIF_FUN(decaf_x25519_direct_scalarmul,		2);
/* decaf/decaf_448.h */
NIF_FUN(decaf_x448_base_scalarmul,		1);
NIF_FUN(decaf_x448_direct_scalarmul,		2);
/* decaf/eddsa_255.h */
NIF_FUN(decaf_255_eddsa_derive_public_key,	1);
NIF_FUN(decaf_255_eddsa_sign,			4);
NIF_FUN(decaf_255_eddsa_verify,			4);
/* decaf/eddsa_448.h */
NIF_FUN(decaf_448_eddsa_derive_public_key,	1);
NIF_FUN(decaf_448_eddsa_sign,			5);
NIF_FUN(decaf_448_eddsa_verify,			5);
/* decaf/sha512.h */
NIF_FUN(sha2_512,				2);
NIF_FUN(sha2_512,				5);	/* private */
NIF_FUN(sha2_512_init,				0);
NIF_FUN(sha2_512_update,			2);
NIF_FUN(sha2_512_update,			4);	/* private */
NIF_FUN(sha2_512_final,				2);
/* decaf/shake.h */
#define SHA3_NIF_DEF(bits)	\
	static ERL_NIF_TERM	libdecaf_sha3_##bits##_nif_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_sha3_##bits##_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_sha3_##bits##_init_nif_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_sha3_##bits##_update_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_sha3_##bits##_update_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_sha3_##bits##_final_nif_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])

#define SHAKE_NIF_DEF(bits)	\
	static ERL_NIF_TERM	libdecaf_shake##bits##_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_shake##bits##_nif_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_shake##bits##_init_nif_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_shake##bits##_update_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_shake##bits##_update_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	libdecaf_shake##bits##_final_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])

SHA3_NIF_DEF(224);
SHA3_NIF_DEF(256);
SHA3_NIF_DEF(384);
SHA3_NIF_DEF(512);
SHAKE_NIF_DEF(128);
SHAKE_NIF_DEF(256);

#undef SHA3_NIF_DEF
#undef SHAKE_NIF_DEF

#undef NIF_FUN

#define NIF_FUNC(function, arity)		{#function, arity, libdecaf_##function##_##arity}
#define NIF_ALIA(alias, function, arity)	{#alias, arity, libdecaf_##function##_##arity}

#undef SHA3_NIF_DEF
#undef SHAKE_NIF_DEF

#define SHA3_NIF_FUN(bits)	\
	{"sha3_" #bits, 1, libdecaf_sha3_##bits##_nif_1},	\
	{"sha3_" #bits "_init", 0, libdecaf_sha3_##bits##_init_nif_0},	\
	{"sha3_" #bits "_update", 2, libdecaf_sha3_##bits##_update_nif_2},	\
	{"sha3_" #bits "_final", 1, libdecaf_sha3_##bits##_final_nif_1}

#define SHAKE_NIF_FUN(bits)	\
	{"shake" #bits, 2, libdecaf_shake##bits##_nif_2},	\
	{"shake" #bits "_init", 0, libdecaf_shake##bits##_init_nif_0},	\
	{"shake" #bits "_update", 2, libdecaf_shake##bits##_update_nif_2},	\
	{"shake" #bits "_final", 2, libdecaf_shake##bits##_final_nif_2}

static ErlNifFunc	libdecaf_nif_funcs[] = {
	/* decaf/decaf_255.h */
	NIF_FUNC(decaf_x25519_base_scalarmul,		1),
	NIF_FUNC(decaf_x25519_direct_scalarmul,		2),
	/* decaf/decaf_448.h */
	NIF_FUNC(decaf_x448_base_scalarmul,		1),
	NIF_FUNC(decaf_x448_direct_scalarmul,		2),
	/* decaf/eddsa_255.h */
	NIF_FUNC(decaf_255_eddsa_derive_public_key,	1),
	NIF_FUNC(decaf_255_eddsa_sign,			4),
	NIF_FUNC(decaf_255_eddsa_verify,		4),
	/* decaf/eddsa_448.h */
	NIF_FUNC(decaf_448_eddsa_derive_public_key,	1),
	NIF_FUNC(decaf_448_eddsa_sign,			5),
	NIF_FUNC(decaf_448_eddsa_verify,		5),
	/* decaf/sha512.h */
	NIF_FUNC(sha2_512,				2),
	NIF_FUNC(sha2_512_init,				0),
	NIF_FUNC(sha2_512_update,			2),
	NIF_FUNC(sha2_512_final,			2),
	/* decaf/shake.h */
	SHA3_NIF_FUN(224),
	SHA3_NIF_FUN(256),
	SHA3_NIF_FUN(384),
	SHA3_NIF_FUN(512),
	SHAKE_NIF_FUN(128),
	SHAKE_NIF_FUN(256),
};

#undef NIF_FUNC
#undef NIF_ALIA

/*
 * Erlang NIF callbacks
 */

typedef struct libdecaf_priv_data_0_s {
	uint8_t			version;
	ErlNifResourceType	*keccak_sponge;
	ErlNifResourceType	*sha2_512_ctx;
} libdecaf_priv_data_0_t;

#define libdecaf_priv_data_version	0
#define libdecaf_priv_data_t		libdecaf_priv_data_0_t

static int		libdecaf_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int		libdecaf_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void		libdecaf_nif_unload(ErlNifEnv *env, void *priv_data);

#endif
