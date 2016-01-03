// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "ed448_api.h"
#include "ed448_api_goldilocks.h"

#define ED448_NS(NAMESPACE)	{ #NAMESPACE, ed448_functions_ ## NAMESPACE }

static ed448_namespace_t	ed448_namespaces[] = {
	ED448_NS(goldilocks),
	// LS_NS(crypto_aead_chacha20poly1305),
	// LS_NS(crypto_auth),
	// LS_NS(crypto_auth_hmacsha256),
	// LS_NS(crypto_auth_hmacsha512),
	// LS_NS(crypto_auth_hmacsha512256),
	// LS_NS(crypto_core_hsalsa20),
	// LS_NS(crypto_core_salsa20),
	// LS_NS(crypto_core_salsa2012),
	// LS_NS(crypto_core_salsa208),
	// LS_NS(crypto_generichash),
	// LS_NS(crypto_generichash_blake2b),
	// LS_NS(crypto_hash),
	// LS_NS(crypto_hash_sha256),
	// LS_NS(crypto_hash_sha512),
	// LS_NS(crypto_onetimeauth),
	// LS_NS(crypto_onetimeauth_poly1305),
	// LS_NS(crypto_scalarmult),
	// LS_NS(crypto_scalarmult_curve25519),
	// LS_NS(crypto_shorthash),
	// LS_NS(crypto_shorthash_siphash24),
	// LS_NS(crypto_sign),
	// LS_NS(crypto_sign_ed25519),
	// LS_NS(crypto_stream),
	// LS_NS(crypto_stream_aes128ctr),
	// LS_NS(crypto_stream_chacha20),
	// LS_NS(crypto_stream_salsa20),
	// LS_NS(crypto_stream_salsa2012),
	// LS_NS(crypto_stream_salsa208),
	// LS_NS(crypto_stream_xsalsa20),
	// LS_NS(randombytes),
	// LS_NS(runtime),
	// LS_NS(utils),
	// LS_NS(version),
	{NULL}
};

void
init_ed448_api(void)
{
	ed448_namespace_t *n;
	ed448_function_t *f;

	n = NULL;
	f = NULL;

	for (n = ed448_namespaces; n->namespace; n++) {
		n->am_namespace = driver_mk_atom((char *)(n->namespace));
		for (f = n->functions; f->function; f++) {
			f->am_function = driver_mk_atom((char *)(f->function));
		}
	}
}

ed448_function_t *
get_ed448_api(const char *namespace, const char *function)
{
	ed448_namespace_t *n;
	ed448_function_t *f;
	ErlDrvTermData am_namespace;
	ErlDrvTermData am_function;

	n = NULL;
	f = NULL;

	// (void) erl_drv_mutex_lock(ed448_mutex);
	am_namespace = driver_mk_atom((char *)namespace);
	am_function = driver_mk_atom((char *)function);
	// (void) erl_drv_mutex_unlock(ed448_mutex);

	for (n = ed448_namespaces; n->namespace; n++) {
		if (n->am_namespace == am_namespace) {
			for (f = n->functions; f->function; f++) {
				if (f->am_function == am_function) {
					return f;
				}
			}
			return NULL;
		}
	}

	return NULL;
}
