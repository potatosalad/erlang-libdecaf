// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef ED448_API_H
#define ED448_API_H

#include "ed448_drv_common.h"
#include "ed448_request.h"

typedef struct ed448_function {
	const char		*function;
	int			arity;
	int			(*init)(ed448_request_t *request, char *buffer, int *index);
	void			(*exec)(ed448_request_t *request);
	ErlDrvTermData		am_function;
} ed448_function_t;

typedef struct ed448_namespace {
	const char		*namespace;
	ed448_function_t	*functions;
	ErlDrvTermData		am_namespace;
} ed448_namespace_t;

extern void		init_ed448_api(void);
extern ed448_function_t	*get_ed448_api(const char *namespace, const char *function);

#define ED448_API_F_NS(NAMESPACE)			ed448_api_ ## NAMESPACE
#define ED448_API_F_FN(FUNCTION)			_ ## FUNCTION
#define ED448_API_F0(A, B)				A ## B
#define ED448_API_F1(A, B)				ED448_API_F0(A, B)
#define ED448_API_F2(NAMESPACE, FUNCTION)		ED448_API_F1(ED448_API_F_NS(NAMESPACE), ED448_API_F_FN(FUNCTION))

#define ED448_API_F_EXEC(NAMESPACE, FUNCTION)	ED448_API_F2(NAMESPACE, FUNCTION)
#define ED448_API_F_INIT(NAMESPACE, FUNCTION)	ED448_API_F1(ED448_API_F_EXEC(NAMESPACE, FUNCTION), _init)
#define ED448_API_F_ARGV(NAMESPACE, FUNCTION)	ED448_API_F1(ED448_API_F_EXEC(NAMESPACE, FUNCTION), _argv)
#define ED448_API_F_ARGV_T(NAMESPACE, FUNCTION)	ED448_API_F1(ED448_API_F_ARGV(NAMESPACE, FUNCTION), _t)

#define ED448_API_EXEC(NAMESPACE, FUNCTION)	ED448_API_F_EXEC(NAMESPACE, FUNCTION) (ed448_request_t *request)
#define ED448_API_INIT(NAMESPACE, FUNCTION)	ED448_API_F_INIT(NAMESPACE, FUNCTION) (ed448_request_t *request, char *buffer, int *index)

#define ED448_API_R_ARG0(NAMESPACE, FUNCTION)		{ #FUNCTION, 0, NULL, ED448_API_F_EXEC(NAMESPACE, FUNCTION) }
#define ED448_API_R_ARGV(NAMESPACE, FUNCTION, ARITY)	{ #FUNCTION, ARITY, ED448_API_F_INIT(NAMESPACE, FUNCTION), ED448_API_F_EXEC(NAMESPACE, FUNCTION) }

#define ED448_API_INIT_ARGV(NAMESPACE, FUNCTION)	\
	do {	\
		argv = (ED448_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(driver_alloc((ErlDrvSizeT)(sizeof (ED448_API_F_ARGV_T(NAMESPACE, FUNCTION)))));	\
		if (argv == NULL) {	\
			return -1;	\
		}	\
	} while (0)

#define ED448_API_READ_ARGV(NAMESPACE, FUNCTION)	\
	do {	\
		argv = (ED448_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(request->argv);	\
	} while (0)

#define ED448_RES_TAG(REQUEST)	ERL_DRV_EXT2TERM, (ErlDrvTermData)(REQUEST->tag.buff), REQUEST->tag.index

#define ED448_RESPOND(REQUEST, SPEC, FILE, LINE)	\
	do {	\
		if (erl_drv_send_term(REQUEST->port->term_port, REQUEST->caller, SPEC, sizeof(SPEC) / sizeof(SPEC[0])) < 0) {	\
			TRACE_F("error sending term\n", FILE, LINE);	\
		}	\
	} while (0)

#endif
