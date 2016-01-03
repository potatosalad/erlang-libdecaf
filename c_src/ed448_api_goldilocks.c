// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "ed448_api_goldilocks.h"

static void	ED448_API_EXEC(goldilocks, keygen);
static int	ED448_API_INIT(goldilocks, derive_private_key);
static void	ED448_API_EXEC(goldilocks, derive_private_key);
static int	ED448_API_INIT(goldilocks, underive_private_key);
static void	ED448_API_EXEC(goldilocks, underive_private_key);
static int	ED448_API_INIT(goldilocks, private_to_public);
static void	ED448_API_EXEC(goldilocks, private_to_public);
static int	ED448_API_INIT(goldilocks, shared_secret);
static void	ED448_API_EXEC(goldilocks, shared_secret);
static int	ED448_API_INIT(goldilocks, sign);
static void	ED448_API_EXEC(goldilocks, sign);
static int	ED448_API_INIT(goldilocks, verify);
static void	ED448_API_EXEC(goldilocks, verify);

ed448_function_t	ed448_functions_goldilocks[] = {
	ED448_API_R_ARG0(goldilocks, keygen),
	ED448_API_R_ARGV(goldilocks, derive_private_key, 1),
	ED448_API_R_ARGV(goldilocks, underive_private_key, 1),
	ED448_API_R_ARGV(goldilocks, private_to_public, 1),
	ED448_API_R_ARGV(goldilocks, shared_secret, 2),
	ED448_API_R_ARGV(goldilocks, sign, 2),
	ED448_API_R_ARGV(goldilocks, verify, 3),
	{NULL}
};

/* goldilocks_keygen/0 */

static void
ED448_API_EXEC(goldilocks, keygen)
{
	struct goldilocks_private_key_t privkey;
	struct goldilocks_public_key_t pubkey;
	int retval;

	retval = goldilocks_keygen(&privkey, &pubkey);

	if (retval == GOLDI_EOK) {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(&privkey), sizeof(privkey),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(&pubkey), sizeof(pubkey),
			ERL_DRV_TUPLE, 2,
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	} else {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_INT, (ErlDrvSInt)(retval),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	}
}

/* goldilocks_derive_private_key/1 */

typedef struct ED448_API_F_ARGV(goldilocks, derive_private_key) {
	const unsigned char	*proto;
} ED448_API_F_ARGV_T(goldilocks, derive_private_key);

static int
ED448_API_INIT(goldilocks, derive_private_key)
{
	ED448_API_F_ARGV_T(goldilocks, derive_private_key) *argv;
	int type;
	int type_length;
	size_t goldi_symkey_bytes;
	ErlDrvSizeT x;
	void *p;

	goldi_symkey_bytes = GOLDI_SYMKEY_BYTES;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_symkey_bytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(goldi_symkey_bytes + (sizeof (ED448_API_F_ARGV_T(goldilocks, derive_private_key))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (ED448_API_F_ARGV_T(goldilocks, derive_private_key) *)(p);
	p += (sizeof (ED448_API_F_ARGV_T(goldilocks, derive_private_key)));
	argv->proto = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->proto), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
ED448_API_EXEC(goldilocks, derive_private_key)
{
	ED448_API_F_ARGV_T(goldilocks, derive_private_key) *argv;
	ED448_API_READ_ARGV(goldilocks, derive_private_key);
	struct goldilocks_private_key_t privkey;
	int retval;

	retval = goldilocks_derive_private_key(&privkey, argv->proto);

	if (retval == GOLDI_EOK) {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(&privkey), sizeof(privkey),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	} else {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_INT, (ErlDrvSInt)(retval),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	}
}

/* goldilocks_underive_private_key/1 */

typedef struct ED448_API_F_ARGV(goldilocks, underive_private_key) {
	const struct goldilocks_private_key_t	*privkey;
} ED448_API_F_ARGV_T(goldilocks, underive_private_key);

static int
ED448_API_INIT(goldilocks, underive_private_key)
{
	ED448_API_F_ARGV_T(goldilocks, underive_private_key) *argv;
	int type;
	int type_length;
	size_t goldi_private_key_bytes;
	ErlDrvSizeT x;
	void *p;

	goldi_private_key_bytes = GOLDI_PRIVATE_KEY_BYTES;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_private_key_bytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(goldi_private_key_bytes + (sizeof (ED448_API_F_ARGV_T(goldilocks, underive_private_key))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (ED448_API_F_ARGV_T(goldilocks, underive_private_key) *)(p);
	p += (sizeof (ED448_API_F_ARGV_T(goldilocks, underive_private_key)));
	argv->privkey = (const struct goldilocks_private_key_t *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->privkey), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
ED448_API_EXEC(goldilocks, underive_private_key)
{
	ED448_API_F_ARGV_T(goldilocks, underive_private_key) *argv;
	ED448_API_READ_ARGV(goldilocks, underive_private_key);
	unsigned char proto[GOLDI_SYMKEY_BYTES];

	(void) goldilocks_underive_private_key(proto, argv->privkey);

	ErlDrvTermData spec[] = {
		ED448_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(&proto), sizeof(proto),
		ERL_DRV_TUPLE, 2
	};
	ED448_RESPOND(request, spec, __FILE__, __LINE__);
}

/* goldilocks_private_to_public/1 */

typedef struct ED448_API_F_ARGV(goldilocks, private_to_public) {
	const struct goldilocks_private_key_t	*privkey;
} ED448_API_F_ARGV_T(goldilocks, private_to_public);

static int
ED448_API_INIT(goldilocks, private_to_public)
{
	ED448_API_F_ARGV_T(goldilocks, private_to_public) *argv;
	int type;
	int type_length;
	size_t goldi_private_key_bytes;
	ErlDrvSizeT x;
	void *p;

	goldi_private_key_bytes = GOLDI_PRIVATE_KEY_BYTES;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_private_key_bytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(goldi_private_key_bytes + (sizeof (ED448_API_F_ARGV_T(goldilocks, private_to_public))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (ED448_API_F_ARGV_T(goldilocks, private_to_public) *)(p);
	p += (sizeof (ED448_API_F_ARGV_T(goldilocks, private_to_public)));
	argv->privkey = (const struct goldilocks_private_key_t *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->privkey), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
ED448_API_EXEC(goldilocks, private_to_public)
{
	ED448_API_F_ARGV_T(goldilocks, private_to_public) *argv;
	ED448_API_READ_ARGV(goldilocks, private_to_public);
	struct goldilocks_public_key_t pubkey;
	int retval;

	retval = goldilocks_private_to_public(&pubkey, argv->privkey);

	if (retval == GOLDI_EOK) {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(&pubkey), sizeof(pubkey),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	} else {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_INT, (ErlDrvSInt)(retval),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	}
}

/* goldilocks_shared_secret/2 */

typedef struct ED448_API_F_ARGV(goldilocks, shared_secret) {
	const struct goldilocks_private_key_t	*my_privkey;
	const struct goldilocks_public_key_t	*your_pubkey;
} ED448_API_F_ARGV_T(goldilocks, shared_secret);

static int
ED448_API_INIT(goldilocks, shared_secret)
{
	ED448_API_F_ARGV_T(goldilocks, shared_secret) *argv;
	int skip;
	int type;
	int type_length;
	size_t goldi_private_key_bytes;
	size_t goldi_public_key_bytes;
	ErlDrvSizeT x;
	void *p;

	goldi_private_key_bytes = GOLDI_PRIVATE_KEY_BYTES;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_private_key_bytes) {
		return -1;
	}

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	goldi_public_key_bytes = GOLDI_PUBLIC_KEY_BYTES;

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_public_key_bytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(goldi_private_key_bytes + goldi_public_key_bytes + (sizeof (ED448_API_F_ARGV_T(goldilocks, shared_secret))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (ED448_API_F_ARGV_T(goldilocks, shared_secret) *)(p);
	p += (sizeof (ED448_API_F_ARGV_T(goldilocks, shared_secret)));
	argv->my_privkey = (const struct goldilocks_private_key_t *)(p);
	p += goldi_private_key_bytes;
	argv->your_pubkey = (const struct goldilocks_public_key_t *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->my_privkey), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->your_pubkey), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
ED448_API_EXEC(goldilocks, shared_secret)
{
	ED448_API_F_ARGV_T(goldilocks, shared_secret) *argv;
	ED448_API_READ_ARGV(goldilocks, shared_secret);
	uint8_t shared[GOLDI_SHARED_SECRET_BYTES];
	int retval;

	retval = goldilocks_shared_secret(shared, argv->my_privkey, argv->your_pubkey);

	if (retval == GOLDI_EOK) {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(&shared), sizeof(shared),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	} else {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_INT, (ErlDrvSInt)(retval),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	}
}

/* goldilocks_sign/2 */

typedef struct ED448_API_F_ARGV(goldilocks, sign) {
	const uint8_t				*message;
	uint64_t				message_len;
	const struct goldilocks_private_key_t	*privkey;
} ED448_API_F_ARGV_T(goldilocks, sign);

static int
ED448_API_INIT(goldilocks, sign)
{
	ED448_API_F_ARGV_T(goldilocks, sign) *argv;
	int skip;
	int type;
	int type_length;
	uint64_t message_len;
	size_t goldi_private_key_bytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	message_len = (uint64_t)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	goldi_private_key_bytes = GOLDI_PRIVATE_KEY_BYTES;

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_private_key_bytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(message_len + goldi_private_key_bytes + (sizeof (ED448_API_F_ARGV_T(goldilocks, sign))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (ED448_API_F_ARGV_T(goldilocks, sign) *)(p);
	p += (sizeof (ED448_API_F_ARGV_T(goldilocks, sign)));
	argv->message = (const uint8_t *)(p);
	p += message_len;
	argv->privkey = (const struct goldilocks_private_key_t *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->message), (long *)&(argv->message_len)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->privkey), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
ED448_API_EXEC(goldilocks, sign)
{
	ED448_API_F_ARGV_T(goldilocks, sign) *argv;
	ED448_API_READ_ARGV(goldilocks, sign);
	uint8_t signature_out[GOLDI_SIGNATURE_BYTES];
	int retval;

	retval = goldilocks_sign(signature_out, argv->message, argv->message_len, argv->privkey);

	if (retval == GOLDI_EOK) {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(&signature_out), sizeof(signature_out),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	} else {
		ErlDrvTermData spec[] = {
			ED448_RES_TAG(request),
			ERL_DRV_INT, (ErlDrvSInt)(retval),
			ERL_DRV_TUPLE, 2
		};
		ED448_RESPOND(request, spec, __FILE__, __LINE__);
	}
}

/* goldilocks_verify/2 */

typedef struct ED448_API_F_ARGV(goldilocks, verify) {
	const uint8_t				*signature;
	const uint8_t				*message;
	uint64_t				message_len;
	const struct goldilocks_public_key_t	*pubkey;
} ED448_API_F_ARGV_T(goldilocks, verify);

static int
ED448_API_INIT(goldilocks, verify)
{
	ED448_API_F_ARGV_T(goldilocks, verify) *argv;
	int skip;
	int type;
	int type_length;
	size_t goldi_signature_bytes;
	uint64_t message_len;
	size_t goldi_public_key_bytes;
	ErlDrvSizeT x;
	void *p;

	goldi_signature_bytes = GOLDI_SIGNATURE_BYTES;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_signature_bytes) {
		return -1;
	}

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	message_len = (uint64_t)(type_length);

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	goldi_public_key_bytes = GOLDI_PUBLIC_KEY_BYTES;

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != goldi_public_key_bytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(goldi_signature_bytes + message_len + goldi_public_key_bytes + (sizeof (ED448_API_F_ARGV_T(goldilocks, verify))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (ED448_API_F_ARGV_T(goldilocks, verify) *)(p);
	p += (sizeof (ED448_API_F_ARGV_T(goldilocks, verify)));
	argv->signature = (const uint8_t *)(p);
	p += goldi_signature_bytes;
	argv->message = (const uint8_t *)(p);
	p += message_len;
	argv->pubkey = (const struct goldilocks_public_key_t *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->signature), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->message), (long *)&(argv->message_len)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->pubkey), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
ED448_API_EXEC(goldilocks, verify)
{
	ED448_API_F_ARGV_T(goldilocks, verify) *argv;
	ED448_API_READ_ARGV(goldilocks, verify);
	int retval;

	retval = goldilocks_verify(argv->signature, argv->message, argv->message_len, argv->pubkey);

	ErlDrvTermData spec[] = {
		ED448_RES_TAG(request),
		ERL_DRV_INT, (ErlDrvSInt)(retval),
		ERL_DRV_TUPLE, 2
	};
	ED448_RESPOND(request, spec, __FILE__, __LINE__);
}
