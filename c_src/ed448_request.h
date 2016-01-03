// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef ED448_REQUEST_H
#define ED448_REQUEST_H

#include "ed448_drv_common.h"
#include "ed448_port.h"

#define ED448_ASYNC_CALL	1

typedef struct ed448_request {
	ed448_port_t	*port;
	ErlDrvTermData		caller;
	void			(*command)(struct ed448_request **, char *, ErlDrvSizeT);
	ei_x_buff		tag;
	ei_term			namespace;
	ei_term			function;
	int			argc;
	void			*argv;
	void			(*execute)(struct ed448_request *);
	int			error;
	ei_x_buff		reply;
} ed448_request_t;

extern ed448_request_t	*ed448_request_alloc(ed448_port_t *port, ErlDrvTermData caller, unsigned int command);
extern void			ed448_request_free(ed448_request_t *request);

#endif