// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "ed448_port.h"

ed448_port_t *
ed448_port_alloc(ErlDrvPort drv_port)
{
	ErlDrvSizeT x;
	void *p;
	ed448_port_t *port;

	x = (ErlDrvSizeT)((sizeof (ed448_port_t)));
	p = driver_alloc(x);

	if (p == NULL) {
		return NULL;
	}

	port = (ed448_port_t *)(p);
	port->drv_port = drv_port;
	port->term_port = driver_mk_port(drv_port);

	return port;
}

void
ed448_port_free(ed448_port_t *port)
{
	if (port == NULL) {
		return;
	}
	(void) driver_free(port);
	port = NULL;
}
