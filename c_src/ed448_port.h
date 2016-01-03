// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef ED448_PORT_H
#define ED448_PORT_H

#include "ed448_drv_common.h"

typedef struct ed448_port {
	ErlDrvPort	drv_port;
	ErlDrvTermData	term_port;
} ed448_port_t;

extern ed448_port_t	*ed448_port_alloc(ErlDrvPort drv_port);
extern void		ed448_port_free(ed448_port_t *port);

#endif