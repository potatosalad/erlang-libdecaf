// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "ed448_drv.h"
#include "ed448_port.h"
#include "ed448_request.h"
#include "ed448_api.h"

#define INIT_ATOM(NAME)		ed448_drv->am_ ## NAME = driver_mk_atom(#NAME)

/*
 * Erlang DRV functions
 */
static int
ed448_drv_init(void)
{
	TRACE_F("ed448_drv_init:%s:%d\n", __FILE__, __LINE__);

	if (ed448_mutex == NULL) {
		ed448_mutex = erl_drv_mutex_create("ed448");
		if (ed448_mutex == NULL) {
			return -1;
		}
	}

	(void) erl_drv_mutex_lock(ed448_mutex);

	if (goldilocks_init() < 0) {
		(void) erl_drv_mutex_unlock(ed448_mutex);
		return -1;
	}

	if (ed448_drv == NULL) {
		ed448_drv = (ed448_drv_term_data_t *)(driver_alloc(sizeof (ed448_drv_term_data_t)));
		if (ed448_drv == NULL) {
			(void) erl_drv_mutex_unlock(ed448_mutex);
			return -1;
		}
		INIT_ATOM(ok);
		INIT_ATOM(error);
		INIT_ATOM(undefined);
	}

	(void) init_ed448_api();

	(void) erl_drv_mutex_unlock(ed448_mutex);

	return 0;
}

static ErlDrvData
ed448_drv_start(ErlDrvPort drv_port, char *command)
{
	ed448_port_t *port;

	(void) command; // Unused

	TRACE_F("ed448_drv_start:%s:%d\n", __FILE__, __LINE__);

	port = ed448_port_alloc(drv_port);

	if (port == NULL) {
		return ERL_DRV_ERROR_GENERAL;
	}

	return (ErlDrvData)(port);
}

static void
ed448_drv_stop(ErlDrvData drv_data)
{
	ed448_port_t *port;

	TRACE_F("ed448_drv_stop:%s:%d\n", __FILE__, __LINE__);

	port = (ed448_port_t *)(drv_data);

	(void) ed448_port_free(port);
}

static void
ed448_drv_finish(void)
{
	TRACE_F("ed448_drv_finish:%s:%d\n", __FILE__, __LINE__);
	if (ed448_mutex != NULL) {
		(void) erl_drv_mutex_lock(ed448_mutex);
	}
	if (ed448_drv != NULL) {
		(void) driver_free(ed448_drv);
		ed448_drv = NULL;
	}
	if (ed448_mutex != NULL) {
		(void) erl_drv_mutex_unlock(ed448_mutex);
		(void) erl_drv_mutex_destroy(ed448_mutex);
		ed448_mutex = NULL;
	}
}

static ErlDrvSSizeT
ed448_drv_call(ErlDrvData drv_data, unsigned int command, char *buf, ErlDrvSizeT len,
		char **rbuf, ErlDrvSizeT rlen, unsigned int *flags)
{
	ed448_port_t *port;
	ErlDrvTermData caller;
	ed448_request_t *request;
	ErlDrvSSizeT retval;

	(void) flags; // Unused

	TRACE_F("ed448_drv_call:%s:%d\n", __FILE__, __LINE__);

	port = (ed448_port_t *)(drv_data);

	if (port == NULL) {
		return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
	}

	// (void) erl_drv_mutex_lock(ed448_mutex);
	caller = driver_caller(port->drv_port);
	// (void) erl_drv_mutex_unlock(ed448_mutex);

	request = ed448_request_alloc(port, caller, command);

	if (request == NULL) {
		LS_FAIL_OOM(port->drv_port);
		return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
	}

	if (request->error < 0) {
		retval = (ErlDrvSSizeT)(request->error);
		(void) ed448_request_free(request);
		return retval;
	}

	(void) (request->command)(&request, buf, len);

	if (request->error < 0) {
		retval = (ErlDrvSSizeT)(request->error);
		(void) ed448_request_free(request);
		return retval;
	}

	retval = (ErlDrvSSizeT)(request->reply.index);

	if (rlen < retval) {
		*rbuf = (char *)(driver_realloc((void *)(*rbuf), (ErlDrvSizeT)(retval)));
		if ((*rbuf) == NULL) {
			(void) ed448_request_free(request);
			LS_FAIL_OOM(port->drv_port);
			return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
		}
	}

	(void) memcpy((void *)(*rbuf), (void *)(request->reply.buff), (size_t)(request->reply.index));

	(void) ed448_request_free(request);

	return retval;
}

DRIVER_INIT(ed448_drv)
{
	return &ed448_driver_entry;
}
