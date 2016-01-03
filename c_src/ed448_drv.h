// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef ED448_DRV_H
#define ED448_DRV_H

#include "ed448_drv_common.h"

ed448_drv_term_data_t	*ed448_drv;
ErlDrvMutex		*ed448_mutex;

/*
 * Erlang DRV functions
 */
static int		ed448_drv_init(void);
static ErlDrvData	ed448_drv_start(ErlDrvPort drv_port, char *command);
static void		ed448_drv_stop(ErlDrvData drv_data);
static void		ed448_drv_finish(void);
static ErlDrvSSizeT	ed448_drv_call(ErlDrvData drv_data, unsigned int command, char *buf, ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen, unsigned int *flags);

static ErlDrvEntry	ed448_driver_entry = {
	ed448_drv_init,			/* F_PTR init, called when driver is loaded */
	ed448_drv_start,		/* L_PTR start, called when port is opened */
	ed448_drv_stop,			/* F_PTR stop, called when port is closed */
	NULL,				/* F_PTR output, called when erlang has sent */
	NULL,				/* F_PTR ready_input, called when input descriptor ready */
	NULL,				/* F_PTR ready_output, called when output descriptor ready */
	"ed448_drv",			/* char *driver_name, the argument to open_port */
	ed448_drv_finish,		/* F_PTR finish, called when unloaded */
	NULL,				/* void *handle, Reserved by VM */
	NULL,				/* F_PTR control, port_command callback */
	NULL,				/* F_PTR timeout, reserved */
	NULL,				/* F_PTR outputv, reserved */
	NULL,				/* F_PTR ready_async, only for async drivers */
	NULL,				/* F_PTR flush, called when port is about to be closed, but there is data in driver queue */
	ed448_drv_call,			/* F_PTR call, much like control, sync call to driver */
	NULL,				/* F_PTR event, called when an event selected by driver_event() occurs. */
	ERL_DRV_EXTENDED_MARKER,	/* int extended marker, Should always be set to indicate driver versioning */
	ERL_DRV_EXTENDED_MAJOR_VERSION,	/* int major_version, should always be set to this value */
	ERL_DRV_EXTENDED_MINOR_VERSION,	/* int minor_version, should always be set to this value */
	ERL_DRV_FLAG_USE_PORT_LOCKING,	/* int driver_flags, see documentation */
	NULL,				/* void *handle2, reserved for VM use */
	NULL,				/* F_PTR process_exit, called when a monitored process dies */
	NULL				/* F_PTR stop_select, called to close an event object */
};

#endif
