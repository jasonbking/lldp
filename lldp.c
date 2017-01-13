/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2012 Jason King.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/conf.h>
#include <stropts.h>
#include <string.h>
#include <atomic.h>
#include <port.h>
#include <libscf.h>
#include <synch.h>
#include <note.h>
#include <err.h>
#include <alloca.h>
#include <unistd.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdarg.h>
#include "lldd.h"
#include "lldp.h"
#include "lldp_int.h"

/*
 * The main architecture is that there are a configurable number of threads
 * that handle incoming PDUs.  The unit of concurrency is a local link (port)
 * so that all the local ports are always handled by the same thread to
 * simplify locking (and to some degree provide isolation for any DOS attacks).
 *
 * Each link implements the 3 state machines described in IEEE 802.1AB-2009.
 * A link becomes active when an event (timer expiration, change in one of
 * the per-link variables, etc) occurs that could trigger a state transition.
 * When that happens, the link is placed on a list of active links that will
 * allow it's state machines to run.  Once the state machine has reached
 * a 'stead-state' (i.e. no more current activities will trigger a state
 * transition), it is idle, and will sleep until it is placed on the active
 * list again.
 */

/*
 * The states of a link
 */
typedef enum lldp_msg_e {
	LLDP_MSG_ADMIN_TX,
	LLDP_MSG_ADMIN_RX,
	LLDP_MSG_ADMIN_TXRX,
	LLDP_MSG_ADMIN_DISABLED,
} lldp_msg_t;

typedef enum lldp_amsg_e {
	LLDP_AMSG_SUSPEND,
	LLDP_AMSG_TQUIT,
	LLDP_AMSG_QUIT
} lldp_amsg_t;

static const uint_t lldp_sap = 0x88cc;
static buf_t lldp_addrs[] = {
	/* nearest bridge */
	{ (uint8_t *)"\x01\x80\xc2\x00\x00\x0e", 6 },
	/* nearest non-TPMR bridge */
	{ (uint8_t *)"\x01\x80\xc2\x00\x00\x03", 6 },
	/* nearest customer bridge */
	{ (uint8_t *)"\x01\x80\xc2\x00\x00\x00", 6 }
};

static uint32_t lldp_tx_interval;
static uint32_t lldp_tx_delay;
static uint32_t lldp_notify_interval;
static uint32_t lldp_tx_hold_multiplier;
static uint32_t lldp_reinit_delay;
static uint32_t lldp_max_neighbors;
static uint32_t lldp_tx_credit_max;
static uint32_t lldp_msg_fast_tx;
static uint32_t	lldp_tx_fast_init;

uint16_t		lldp_cap;
uint16_t		lldp_encap;
struct sockaddr_storage *lldp_mgmt_addrs;
size_t			lldp_num_mgmt_addrs;

static volatile time_t lldp_last_change;
static volatile uint32_t lldp_inserts;
static volatile uint32_t lldp_deletes;
static volatile uint32_t lldp_drops;
static volatile uint32_t lldp_ageouts;

static lldp_worker_t	**lldp_workers;
static int		lldp_num_workers;
__thread lldp_worker_t  *lldp_worker;

static void lldp_delete_info(void *);
static void lldp_too_many_neighbors(void *);

static void lldp_state_machine(lldp_link_t *);
static void lldp_dump_neighbor(lldp_link_t *, const lldp_neighbor_t *);

/* XXX: add minimum values */
static scf_cfg_t lldp_scf_cfg[] = {
	{ "tx_interval", SCF_TYPE_COUNT, &lldp_tx_interval, UINT_MAX },
	{ "tx_delay", SCF_TYPE_COUNT, &lldp_tx_delay, UINT_MAX },
	{ "notify_interval", SCF_TYPE_COUNT, &lldp_notify_interval, UINT_MAX },
	{ "tx_hold_multiplier", SCF_TYPE_COUNT, &lldp_tx_hold_multiplier,
		UINT_MAX },
	{ "tx_credit_max", SCF_TYPE_COUNT, &lldp_tx_credit_max, 10 },
	{ "tx_msg_fast_tx", SCF_TYPE_COUNT, &lldp_msg_fast_tx, 3600 },
	{ "tx_fast_init", SCF_TYPE_COUNT, &lldp_tx_fast_init, 8 },
	{ "reinit_delay", SCF_TYPE_COUNT, &lldp_reinit_delay, UINT_MAX },
	{ NULL, SCF_TYPE_INVALID, NULL, 0 }
};

void
lldp_read_config(void)
{
	/* 802.1ad recommended defaults */
	lldp_tx_interval = 30;
	lldp_tx_delay = 2;
	lldp_notify_interval = 5;
	lldp_tx_hold_multiplier = 4;
	lldp_reinit_delay = 2;
	lldp_tx_credit_max = 5;
	lldp_msg_fast_tx = 1;
	lldp_tx_fast_init = 4;

	/* our own defaults */
	lldp_max_neighbors = 512; 	/* per link */

	lldp_cap = lldp_encap = LLDP_CAP_STATION;

	/* XXX: get mgmt addrs */
	lldp_mgmt_addrs = NULL;
	lldp_num_mgmt_addrs = 0;

	read_scf_proto_cfg("lldp", lldp_scf_cfg);
}

/*
 * Put the link on the active list.  If already there, we just
 * leave it as order on the list is unimportant.
 */
void
lldp_set_active(lldp_link_t *link)
{
	if (list_link_active(&link->list_active))
		return;
	list_insert_tail(&lldp_worker->active, (void *)link);
}

static void
lldp_schedule(lldp_link_t *link)
{
	int rc;

	rc = port_associate(link->worker->port, PORT_SOURCE_FD,
	    dlpi_fd(link->dlh), POLLIN, (void *)link);

	if (rc == -1)
		DMSG(D_NET, "%s: port_associate(%s) failed: %s", __func__,
		    dlpi_linkname(link->dlh), strerror(errno));
}

/*
 * Callback for any inbound data on an opened device.
 * Due to the way libdlpi works, to get any DLPI notifications
 * you must have the port open and bound, even if you don't otherwise
 * care about receiving frames.
 */
static void
lldp_inbound(lldp_link_t *link)
{
	dlpi_recvinfo_t ri;
	int rc, len = 1500;

	/*
	 * if we're not looking for PDUs, don't alert or otherwise do much
	 * with it.  It's probabably just a DLPI notification that triggered
	 * a POLLIN event.
	 */
	if (link->rx_state != RX_WAIT_FOR_FRAME)
		goto drain;

	if (link->num_neighbors > link->max_neighbors) {
		DMSG(D_LLDP, "lldp: too many neighbors; discarding PDU.");
		link->rx_discarded++;
		goto drain;
	}

	/* peek at the amount waiting for us */
	rc = ioctl(dlpi_fd(link->dlh), I_NREAD, &len);
	if (rc == -1) {
		DMSG(D_NET|D_LLDP, "lldp: ioctl(%s, I_NREAD) failed: %s",
		    dlpi_linkname(link->dlh), strerror(errno));
		goto drain;
	}

	/* XXX: not sure if this is necessary */
	if (len == 0)
		goto drain;

	lldp_set_size(len);
	lldp_worker->pdu.len = lldp_worker->pdu_alloc;
	lldp_worker->srclen = sizeof (lldp_worker->src);

	rc = dlpi_recv(link->dlh, lldp_worker->src, &lldp_worker->srclen,
	    lldp_worker->pdu.data, &lldp_worker->pdu.len, -1, &ri);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_LLDP, "lldp: dlpi_recv(%s) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
		lldp_schedule(link);
		return;
	}

	if (ri.dri_totmsglen > lldp_worker->pdu_alloc) {
		DMSG(D_NET|D_LLDP, "lldp: dlpi_recv(%s) failed: message  "
		    "was too large (%'zu bytes).",
		    dlpi_linkname(link->dlh), ri.dri_totmsglen);
		lldp_schedule(link);
		return;
	}

	/*
	 * was just a DLPI notification, dlpi_recv() will have invoked
	 * the configured notification handler already, so just reset
	 */
	if (lldp_worker->pdu.len == 0) {
		lldp_schedule(link);
		return;
	}

	(void) memcpy(lldp_worker->dest, ri.dri_destaddr, ri.dri_destaddrlen);
	lldp_worker->destlen = ri.dri_destaddrlen;

	/* let the rx state machine know there's a PDU waiting */
	link->recv_frame = B_TRUE;
	lldp_set_active(link);
	DMSG(D_NET|D_LLDP, "lldp: received a %'zu byte PDU", ri.dri_totmsglen);

	lldp_schedule(link);
	return;

drain:
	rc = dlpi_recv(link->dlh, NULL, NULL, NULL, NULL, 0, NULL);
	if (rc != DLPI_SUCCESS)
		DMSG(D_NET, "lldp: dlpi_recv(%s) (drain) failed: %s", __func__,
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
	lldp_schedule(link);
}

/*
 * For any link that has become active, run its state machine
 * and remove from the active list.
 */
void
lldp_run_active(void)
{
	lldp_link_t *link, *next;

	link = (lldp_link_t *)list_head(&lldp_worker->active);
	while (link != NULL) {
		next = (lldp_link_t *)list_next(&lldp_worker->active, link);
		lldp_state_machine(link);
		list_remove(&lldp_worker->active, link);
		link = next;
	}

	ASSERT(list_is_empty(&lldp_worker->active));
}

/*
 * Called upon clean shutdown -- send out shutdown PDU on every link
 */
static void
lldp_shutdown(void)
{
	lldp_link_t *link;

	link = (lldp_link_t *)list_head(&lldp_worker->links);
	while (link != NULL) {
		link->admin_status = LLDP_LINK_DISABLED;
		lldp_state_machine(link);
		dlpi_close(link->dlh);
		link->dlh = NULL;

		link = (lldp_link_t *)list_next(&lldp_worker->links,
		    (void *)link);
	}
}

static void *
lldp_loop(void *data)
{
	lldp_link_t *link, *next;
	boolean_t quit = B_FALSE;

	lldp_worker = (lldp_worker_t *)data;

	DMSG(D_THREAD, "%s: enter; port fd = %d", __func__, lldp_worker->port);

	while (!quit) {
		int rc;
		port_event_t pe;
		timespec_t timeout;
		timespec_t *tp;
		boolean_t new_status = B_FALSE;

		ASSERT(list_is_empty(&lldp_worker->active));

		tp = lldp_get_timeout(&timeout);
		rc = port_get(lldp_worker->port, &pe, tp);

		if (rc != 0 && errno != ETIME) {
			DMSG(D_LLDP, "lldp: port_get() failed: %d %s", errno,
			    strerror(errno));
			sleep(1);
			continue;
		}

		if (rc != 0) {
			lldp_process_timers();
			continue;
		}

		link = NULL;
		switch (pe.portev_source) {
		case PORT_SOURCE_FD:
			link = (lldp_link_t *)pe.portev_user;
			lldp_inbound(link);
			break;

		case PORT_SOURCE_ALERT:
			switch (pe.portev_events) {
			case LLDP_AMSG_SUSPEND:
				/* XXX: not yet */
				break;
			case LLDP_AMSG_TQUIT:
				quit = B_TRUE;
				/* XXX: other cleanup */
				break;
			case LLDP_AMSG_QUIT:
				lldp_shutdown();
				return (NULL);
			}
			break;

		case PORT_SOURCE_USER:
			switch (pe.portev_events) {
			case LLDP_MSG_ADMIN_TX:
				link = (lldp_link_t *)pe.portev_user;
				link->admin_status = LLDP_LINK_TX;
				new_status = B_TRUE;
				lldp_set_active(link);
				break;
			case LLDP_MSG_ADMIN_RX:
				link = (lldp_link_t *)pe.portev_user;
				link->admin_status = LLDP_LINK_RX;
				new_status = B_TRUE;
				lldp_set_active(link);
				break;
			case LLDP_MSG_ADMIN_TXRX:
				link = (lldp_link_t *)pe.portev_user;
				link->admin_status = LLDP_LINK_TXRX;
				new_status = B_TRUE;
				lldp_set_active(link);
				break;
			case LLDP_MSG_ADMIN_DISABLED:
				link = (lldp_link_t *)pe.portev_user;
				link->admin_status = LLDP_LINK_DISABLED;
				new_status = B_TRUE;
				lldp_set_active(link);
				break;
			default:
				DMSG(D_LLDP, "lldp: unknown message %d "
				    "received", pe.portev_events);
				VERIFY(0);
			}
			break;
		}

		if (new_status)
			DMSG(D_LLDP, "lldp: setting admin status on %s to %s",
			    dlpi_linkname(link->dlh),
			    lldp_status_str(link->admin_status));

		lldp_run_active();
	}

	return (NULL);
}

/*
 * DLPI notification handler
 */
static void
lldp_dlpi_notify(dlpi_handle_t dlh, dlpi_notifyinfo_t *ni, void *arg)
{
	lldp_link_t *link = (lldp_link_t *)arg;

	switch (ni->dni_note) {
	case DL_NOTE_LINK_DOWN:
		link->enabled = B_FALSE;
		DMSG(D_NET|D_LLDP, "lldp: link down on %s",
		    dlpi_linkname(dlh));
		break;
	case DL_NOTE_LINK_UP:
		link->enabled = B_TRUE;
		DMSG(D_NET|D_LLDP, "lldp: link up on %s",
		    dlpi_linkname(dlh));
		break;
	case DL_NOTE_SDU_SIZE:
		link->mtu = ni->dni_size;
		DMSG(D_NET|D_LLDP, "lldp: MTU size changed to %'u bytes.",
		    link->mtu);
		break;
	case DL_NOTE_SPEED:
	case DL_NOTE_PHYS_ADDR:
		break;
	default:
		DMSG(D_LLDP, "lldp: unknown DLPI notification %u received "
		    "on %s", ni->dni_note, dlpi_linkname(dlh));
	}
	/* XXX: this should probably put the link on the active list */
}

static boolean_t
lldp_open(lldp_link_t *link)
{
	uint_t notes;
	int i, rc;

	DMSG(D_NET|D_LLDP, "lldp: opening %s", link->lld->name);

	rc = dlpi_open(link->lld->name, &link->dlh, DLPI_PASSIVE);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_LLDP, "lldp: dlpi_open(%s) failed: %s",
		    link->lld->name, dlpi_strerror(rc));
		return (B_FALSE);
	}

	DMSG(D_NET, "lldp: %s DLPI fd is %d", dlpi_linkname(link->dlh),
	    dlpi_fd(link->dlh));

	/*
	 * there are currently 3 different multicast addresses defined
	 * that LLDP PDUs can be sent to, depending on the intended
	 * recipient in a bridged topology.  For now at least, we
	 * listen for all of them.
	 */
	for (i = 0; i < sizeof (lldp_addrs) / sizeof (buf_t); i++) {
		char str[DLPI_PHYSADDR_MAX * 3];

		fmt_macaddr(str, sizeof (str), lldp_addrs[i].data,
		    lldp_addrs[i].len);
		DMSG(D_NET|D_LLDP, "lldp: enabling mulicast reception to %s "
		    "on %s", str, dlpi_linkname(link->dlh));

		rc = dlpi_enabmulti(link->dlh, lldp_addrs[i].data,
		    lldp_addrs[i].len);
		if (rc != DLPI_SUCCESS) {
			DMSG(D_NET|D_LLDP, "lldp: dlpi_enabmulti(%s, %s) "
			    "failed: %s", dlpi_linkname(link->dlh), str,
			    dlpi_strerror(rc));
			dlpi_close(link->dlh);
			link->dlh = NULL;
			return (B_FALSE);
		}
	}

	DMSG(D_NET|D_LLDP, "lldp: binding to SAP %#x on %s", lldp_sap,
	    dlpi_linkname(link->dlh));

	rc = dlpi_bind(link->dlh, lldp_sap, NULL);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_LLDP, "lldp: dlpi_bind(%s, %#x) failed: %s",
		    dlpi_linkname(link->dlh), lldp_sap, dlpi_strerror(rc));
		dlpi_close(link->dlh);
		link->dlh = NULL;
		return (B_FALSE);
	}

	notes = DL_NOTE_PHYS_ADDR | DL_NOTE_LINK_DOWN | DL_NOTE_LINK_UP |
	    DL_NOTE_SDU_SIZE | DL_NOTE_SPEED;

	rc = dlpi_enabnotify(link->dlh, notes, lldp_dlpi_notify,
	    (void *)link, &link->dl_nid);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_LLDP, "lldp: dlpi_enabnotify(%s) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
		dlpi_close(link->dlh);
		link->dlh = NULL;
		return (B_FALSE);
	}

	return (B_TRUE);
}

void
lldp_init(int numworkers)
{
	char str[256];

	lldp_worker_t *worker = NULL;
	lldp_link_t *link = NULL;
	link_t *lld = NULL;
	int i, rc;
	struct sigevent se;

	lldp_worker = NULL;

	DMSG(D_LLDP, "%s: enter; # of workers = %d", __func__, numworkers);

	lldp_obj_init();

	/* create worker data */
	lldp_workers = calloc(numworkers, sizeof (lldp_worker_t *));
	if (lldp_workers == NULL)
		err(EXIT_FAILURE, "calloc");

	for (i = 0; i < numworkers; i++) {
		if ((lldp_workers[i] = lldp_worker_alloc()) == NULL)
			err(EXIT_FAILURE, "lldp_worker_alloc");
	}
	lldp_num_workers = numworkers;

	/* distribute links among workers */
	lld = (link_t *)list_head(&links);
	i = 0;
	while (lld != NULL) {
		link = lldp_link_alloc(lld);
		if (link == NULL)
			err(EXIT_FAILURE, "lldp_link_alloc");

		if (!lldp_open(link))
			errx(EXIT_FAILURE, "unable to open port");

		link->worker = worker = lldp_workers[i++ % numworkers];
		list_insert_tail(&worker->links, (void *)link);

		/* XXX: this really doesn't belong here */
		link->max_neighbors = lldp_max_neighbors;

		lldp_schedule(link);

		lld = (link_t *)list_next(&links, (void *)lld);
	}

	/* create workers */
	for (i = 0; i < numworkers; i++) {
		rc = pthread_create(&lldp_workers[i]->tid, NULL,
		    lldp_loop, lldp_workers[i]);
		if (rc != 0)
			errx(EXIT_FAILURE, "pthread_create: %s", strerror(rc));
	}
}

/*
 * Called whenever something changes in our neighbor data.
 * For now this is much like the goggles, in that it does nothing.
 */
static void
lldp_remote_change(lldp_link_t *link)
{
	NOTE(ARGUNUSED(link))
	/* XXX: do something! */
}

static void
lldp_tx_initialize(lldp_link_t *link)
{
	/* XXX: move setting of link data used in outbound PDUs here */
}

static void
lldp_rx_initialize(lldp_link_t *link)
{
	lldp_neighbor_t *nb, *nb_next;

	lldp_neighbor_free(lldp_worker->nb);
	lldp_worker->nb = NULL;

	nb = (lldp_neighbor_t *)list_head(&link->neighbors);
	while (nb != NULL) {
		nb_next = (lldp_neighbor_t *)list_next(&link->neighbors, nb);
		lldp_neighbor_free(nb);
		nb = nb_next;
	}

	ASSERT(list_is_empty(&link->neighbors));
}

static void
lldp_update_info(lldp_link_t *link)
{
	lldp_neighbor_t *nb;

	ASSERT(link->rx_state == UPDATE_INFO);

	link->num_neighbors++;
	nb = lldp_worker->nb;
	lldp_worker->nb = NULL;
	lldp_neighbor_add(link, nb);

	if (link->num_neighbors == link->max_neighbors)
		link->too_many = gethrtime() + (hrtime_t)link->rx_ttl * NANOSEC;
}

/*
 * tx credits are used to throttle the number of PDUs sent on a link.
 *
 * Whenever a PDU is sent, a credit is used.  Credits are restored at
 * a rate of one/sec (via the tick timer).  When a link has exhausted its
 * credits, it will not brodcast until it receives more credits.
 */
static void
lldp_dec_credit(lldp_link_t *link)
{
	ASSERT(link->tx_state == TX_INFO_FRAME);

	if (link->tx_credit > 0)
		link->tx_credit--;

	/*
	 * if we've used any credits, we need to start receiving tick timer
	 * firings to replenish the credits.
	 */
	lldp_set_tick(link, B_TRUE);
}

/*
 * As described abovie, this is called whenever the tick timer fires
 * for a link to replenish the number of credits for a link.
 */
static void
lldp_inc_credit(lldp_link_t *link)
{
	boolean_t stop_tick;

	ASSERT(link->timer_state == TX_TICK);

	if (link->tx_credit < lldp_tx_credit_max)
		link->tx_credit++;

	/* Once we reach our max, we don't need to get notified anymore */
	if (link->tx_credit == lldp_tx_credit_max)
		lldp_set_tick(link, B_FALSE);
}

/*
 * Remove any aged out neighbors (based on TTL) from our data
 */
static void
lldp_delete_info(void *arg)
{
	lldp_link_t *link = (lldp_link_t *)arg;
	lldp_neighbor_t *nb, *next;
	hrtime_t now;

	ASSERT(link->rx_state == DELETE_INFO ||
	    link->rx_state == DELETE_AGED_INFO);

	now = gethrtime();
	nb = (lldp_neighbor_t *)list_head(&link->neighbors);
	while (nb != NULL) {
		if (nb->timer.when > now)
			break;

		next = (lldp_neighbor_t *)list_next(&link->neighbors, nb);
		list_remove(&link->neighbors, nb);
		link->num_neighbors--;

		if (dlevel & D_LLDP) {
			char cstr[256];
			char pstr[256];

			(void) lldp_chassis_str(cstr, sizeof (cstr),
			    nb->chassis_subtype,
			    nb->chassis_id,
			    nb->chassis_len);
			(void) lldp_port_str(pstr, sizeof (pstr),
			    nb->port_subtype,
			    nb->port_id,
			    nb->port_len);
			DMSG(D_LLDP, "lldp: purging neighbor %s:%s from %s",
			    (nb->sysname != NULL) ? nb->sysname : cstr,
			    pstr, dlpi_linkname(link->dlh));
		}
		lldp_neighbor_free(nb);
		atomic_inc_32(&lldp_ageouts);
		nb = next;
	}
}

static void
lldp_send(lldp_link_t *link, ssize_t len)
{
	int rc;

	DMSG(D_LLDP|D_NET, "lldp: %s sending %'zd byte PDU",
	    dlpi_linkname(link->dlh), len);

	rc = dlpi_send(link->dlh, lldp_addrs[0].data, lldp_addrs[0].len,
	    lldp_worker->pdu.data, len, NULL);
	if (rc != DLPI_SUCCESS)
		DMSG(D_LLDP|D_NET, "lldp: dlpi_send(%s) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
}

/*
 * The state machines follow almost directly from the description and
 * diagrams in 802.1AB-2009.  For each state machine, it's broken into
 * two parts:
 * 	- Things that occur upon first entering a state
 * 	- A calculation of what the next state is based on the current
 * 	settings of the link.
 */
static boolean_t
lldp_tx_newstate(lldp_link_t *link, lldp_tx_state_t newstate)
{
	lldp_tx_state_t oldstate = link->tx_state;
	ssize_t len;

	if (link->tx_state == newstate) {
		DMSG(D_STATE, "lldp: %s TX idling in %s",
		    link->lld->name, lldp_tx_statestr(link->tx_state));
		return (B_FALSE);
	}

	DMSG(D_STATE, "lldp: %s TX %s -> %s", dlpi_linkname(link->dlh),
	    lldp_tx_statestr(oldstate), lldp_tx_statestr(newstate));

	link->tx_state = newstate;
	switch (newstate) {
	case TX_LLDP_INITIALIZE:
		lldp_tx_initialize(link);
		break;

	case TX_IDLE: {
		uint64_t ttl = lldp_tx_interval * lldp_tx_hold_multiplier + 1;

		link->tx_ttl = (ttl > USHRT_MAX) ? USHRT_MAX : (uint16_t)ttl;
		break;
	}

	case TX_SHUTDOWN_FRAME:
		len = lldp_create_pdu(link, 0);
		if (len > 0)
			lldp_send(link, len);

		lldp_set_timer(link, LLDP_TIMER_SHUTDOWN, lldp_reinit_delay);
		break;

	case TX_INFO_FRAME:
		len = lldp_create_pdu(link, link->tx_ttl);
		lldp_send(link, len);
		lldp_dec_credit(link);
		link->tx_now = B_FALSE;
		break;
	default:
		VERIFY(0);
	}

	return (B_TRUE);
}

static lldp_tx_state_t
lldp_tx_nextstate(lldp_link_t *link)
{
	lldp_tx_state_t newstate = link->tx_state;

	if (!link->enabled) {
		newstate = TX_LLDP_INITIALIZE;
		goto done;
	}

	switch (link->tx_state) {
	case TX_BEGIN:
		newstate = TX_LLDP_INITIALIZE;
		break;

	case TX_LLDP_INITIALIZE:
		if (link->admin_status == LLDP_LINK_TX ||
		    link->admin_status == LLDP_LINK_TXRX) {
			newstate = TX_IDLE;
			break;
		}
		break;

	case TX_IDLE:
		/*
		 * these should be mutually exclusive, but we let
		 * a disabled link win out if not
		 */
		if (link->tx_now == B_TRUE && link->tx_credit > 0) {
			newstate = TX_INFO_FRAME;
			break;
		}
		if (link->admin_status == LLDP_LINK_DISABLED ||
		    link->admin_status == LLDP_LINK_RX) {
			newstate = TX_SHUTDOWN_FRAME;
			break;
		}
		break;

	case TX_SHUTDOWN_FRAME:
		if (lldp_timer_val(link, LLDP_TIMER_SHUTDOWN) <= 0)
			newstate = TX_LLDP_INITIALIZE;
		break;

	case TX_INFO_FRAME:
		newstate = TX_IDLE;
		break;

	default:
		VERIFY(0);
	}

done:
	return (newstate);
}

static boolean_t
lldp_rx_newstate(lldp_link_t *link, lldp_rx_state_t newstate)
{
	lldp_rx_state_t oldstate = link->rx_state;

	if (newstate == link->rx_state) {
		DMSG(D_STATE, "lldp: %s RX idle in %s",
		    link->lld->name, lldp_rx_statestr(link->rx_state));
		return (B_FALSE);
	}

	DMSG(D_STATE, "lldp: %s RX %s -> %s", dlpi_linkname(link->dlh),
	    lldp_rx_statestr(oldstate), lldp_rx_statestr(newstate));

	link->rx_state = newstate;
	switch (newstate) {
	case LLDP_WAIT_PORT_OPERATIONAL:
		break;

	case DELETE_AGED_INFO:
		lldp_delete_info(link);
		link->rx_info_age = B_FALSE;
		lldp_remote_change(link);
		break;

	case RX_LLDP_INITIALIZE:
		lldp_rx_initialize(link);
		link->recv_frame = B_FALSE;
		break;

	case RX_WAIT_FOR_FRAME:
		link->bad_frame = B_FALSE;
		link->rx_info_age = B_FALSE;
		break;

	case RX_FRAME:
		link->rx_changes = B_FALSE;
		link->recv_frame = B_FALSE;
		lldp_process_frame(link);
		break;

	case DELETE_INFO:
		lldp_delete_info(link);
		lldp_remote_change(link);
		break;

	case UPDATE_INFO:
		lldp_update_info(link);
		lldp_remote_change(link);
		break;

	default:
		VERIFY(0);
	}

	return (B_TRUE);
}

static lldp_rx_state_t
lldp_rx_nextstate(lldp_link_t *link)
{
	if (!link->enabled && !link->rx_info_age)
		return (LLDP_WAIT_PORT_OPERATIONAL);

	switch (link->rx_state) {
	case RX_BEGIN:
		return (LLDP_WAIT_PORT_OPERATIONAL);

	case LLDP_WAIT_PORT_OPERATIONAL:
		if (link->rx_info_age)
			return (DELETE_AGED_INFO);
		if (link->enabled)
			return (RX_LLDP_INITIALIZE);
		break;

	case DELETE_AGED_INFO:
		return (LLDP_WAIT_PORT_OPERATIONAL);

	case RX_LLDP_INITIALIZE:
		if (link->admin_status == LLDP_LINK_TXRX ||
		    link->admin_status == LLDP_LINK_RX)
			return (RX_WAIT_FOR_FRAME);
		break;

	case RX_WAIT_FOR_FRAME:
		if (link->rx_info_age)
			return (DELETE_INFO);
		if (link->recv_frame) {
			if (link->too_many != 0 &&
			    gethrtime() < link->too_many) {
				link->rx_discarded++;
				link->recv_frame = B_FALSE;
				break;
			}
			return (RX_FRAME);
		}
		if (link->admin_status == LLDP_LINK_DISABLED ||
		    link->admin_status == LLDP_LINK_TX)
			return (RX_LLDP_INITIALIZE);
		break;

	case RX_FRAME:
		if (!link->bad_frame)
			lldp_dump_neighbor(link, lldp_worker->nb);

		/* check for a bad frame first */
		if (link->bad_frame ||
		    (link->rx_ttl != 0 && !link->rx_changes))
			return (RX_WAIT_FOR_FRAME);
		if (link->rx_ttl == 0)
			return (DELETE_INFO);
		if (link->rx_ttl != 0 && link->rx_changes)
			return (UPDATE_INFO);
		break;

	case DELETE_INFO:
		return (RX_WAIT_FOR_FRAME);

	case UPDATE_INFO:
		return (RX_WAIT_FOR_FRAME);

	default:
		VERIFY(0);
	}

	return (link->rx_state);
}

static boolean_t
lldp_timer_newstate(lldp_link_t *link, lldp_timer_state_t newstate)
{
	if (link->timer_state == newstate) {
		DMSG(D_LLDP, "lldp: %s TIMER idle in %s",
		    link->lld->name, lldp_timer_statestr(link->timer_state));
		return (B_FALSE);
	}

	DMSG(D_LLDP, "lldp: %s TIMER %s -> %s", link->lld->name,
	    lldp_timer_statestr(link->timer_state),
	    lldp_timer_statestr(newstate));

	link->timer_state = newstate;

	switch (newstate) {
	case TX_TIMER_INITIALIZE:
		link->tx_tick = B_FALSE;
		link->tx_now = B_FALSE;
		link->local_changes = B_FALSE;
		link->tx_fast = 0;
		link->new_neighbor = B_FALSE;
		link->tx_credit = lldp_tx_credit_max;
		lldp_set_tick(link, B_FALSE);
		lldp_set_timer(link, LLDP_TIMER_TX, 0);
		lldp_set_timer(link, LLDP_TIMER_SHUTDOWN, 0);
		break;

	case TX_TIMER_IDLE:
		break;

	case TX_TIMER_EXPIRES:
		if (link->tx_fast > 0)
			link->tx_fast--;
		break;

	case TX_TICK:
		link->tx_tick = B_FALSE;
		lldp_inc_credit(link);
		break;

	case SIGNAL_TX:
		link->tx_now = B_TRUE;
		link->local_changes = B_FALSE;
		lldp_set_timer(link, LLDP_TIMER_TX,
		    (link->tx_fast > 0) ? lldp_msg_fast_tx : lldp_tx_interval);
		break;

	case TX_FAST_START:
		link->new_neighbor = B_FALSE;
		if (link->tx_fast == 0)
			link->tx_fast = lldp_tx_fast_init;
		break;

	default:
		VERIFY(0);
	}

	return (B_TRUE);
}

static lldp_timer_state_t
lldp_timer_nextstate(lldp_link_t *link)
{
	if (!link->enabled || link->admin_status == LLDP_LINK_DISABLED ||
	    link->admin_status == LLDP_LINK_RX)
		return (TX_TIMER_INITIALIZE);

	switch (link->timer_state) {
	case TIMER_BEGIN:
		return (TX_TIMER_INITIALIZE);

	case TX_TIMER_INITIALIZE:
		if (link->admin_status == LLDP_LINK_TX ||
		    link->admin_status == LLDP_LINK_TXRX)
			return (TX_TIMER_IDLE);
		break;

	case TX_TIMER_IDLE:
		if (link->local_changes)
			return (SIGNAL_TX);
		if (lldp_timer_val(link, LLDP_TIMER_TX) <= 0)
			return (TX_TIMER_EXPIRES);
		if (link->new_neighbor)
			return (TX_FAST_START);
		if (link->tx_tick)
			return (TX_TICK);
		break;

	case TX_TIMER_EXPIRES:
		return (SIGNAL_TX);

	case TX_TICK:
		return (TX_TIMER_IDLE);

	case SIGNAL_TX:
		return (TX_TIMER_IDLE);

	case TX_FAST_START:
		return (TX_TIMER_EXPIRES);

	default:
		VERIFY(0);
	}
	return (link->timer_state);
}

/*
 * The main LLDP state machine.  While tx, rx, and timer are separated out
 * we just implement each sequentially.
 *
 * We loop until we no longer have any work to do, denoted by a lack
 * of a state transition.
 */
static void
lldp_state_machine(lldp_link_t *link)
{

	boolean_t more = B_TRUE;

	VERIFY(pthread_mutex_lock(&link->lld->lock) == 0);
	DMSG(D_STATE, "lldp: updating state on %s", dlpi_linkname(link->dlh));

	/*
	 * The order of execution of the state machines was chosen based
	 * on the typical flow of events.  Timers will trigger tx & rx
	 * events, but rx events can also trigger tx events (e.g. fast
	 * start).
	 */
	while (lldp_timer_newstate(link, lldp_timer_nextstate(link)));
	while (lldp_rx_newstate(link, lldp_rx_nextstate(link)));
	while (lldp_tx_newstate(link, lldp_tx_nextstate(link)));

	VERIFY(pthread_mutex_unlock(&link->lld->lock) == 0);
}

/*
 * Called by outside threads to update the status of a link.
 * Genereates a message that is sent to the thread's event port.
 */
void
lldp_set_admin_status(lldp_link_t *link, lldp_admin_status_t state)
{
	lldp_msg_t msg;

	switch (state) {
	case LLDP_LINK_TX:
		msg = LLDP_MSG_ADMIN_TX;
		break;
	case LLDP_LINK_RX:
		msg = LLDP_MSG_ADMIN_RX;
		break;
	case LLDP_LINK_TXRX:
		msg = LLDP_MSG_ADMIN_TXRX;
		break;
	case LLDP_LINK_DISABLED:
		msg = LLDP_MSG_ADMIN_DISABLED;
		break;
	default:
		DMSG(D_LLDP, "%s: invalid state request %d for %s", __func__,
		    state, dlpi_linkname(link->dlh));
		return;
	}

	if (port_send(link->worker->port, msg, link) == 0)
		return;

	DMSG(D_LLDP, "%s: port_send(%s) failed: %s", __func__,
	    dlpi_linkname(link->dlh), strerror(errno));
}

/*
 * Called on graceful shutdown.  Send thread shutdown notification
 * to all worker threads (to allow for hte transmissions of a shutdown PDU).
 */
void
lldp_quit(void)
{
	void *dummy;
	int i, rc;

	for (i = 0; i < lldp_num_workers; i++) {
		rc = port_alert(lldp_workers[i]->port, PORT_ALERT_SET,
		    LLDP_AMSG_QUIT, NULL);
		if (rc != 0) {
			DMSG(D_LLDP|D_THREAD, "lldp: port_alert(worker %d, "
			    "LLDP_AMSG_QUIT) failed: %s",
			    lldp_workers[i]->tid, strerror(errno));
			continue;
		}
		/*
		 * XXX: it might be better to detach the thread & have the
		 * main thread wait w/ a timeout instead of this
		 */
		(void) pthread_join(lldp_workers[i]->tid, &dummy);
	}
}

/*
 * Attempts to resize the worker buffer for PDUs to guarantee a minimum
 * amount of space.
 */
void
lldp_set_size(size_t len)
{
	uint8_t *newbuf;

	if (lldp_worker->pdu_alloc >= len)
		return;

	newbuf = realloc(lldp_worker->pdu.data, len);
	if (newbuf == NULL)
		return;

	lldp_worker->pdu.data = newbuf;
	lldp_worker->pdu_alloc = len;
}

static void
lldp_dump_mgmtaddr(const lldp_mgmt_addr_t *addr)
{
	char str[256];
	int i;

	// lldp_mgmt_addr_substr(xx)
	(void) printf("%*s: %s\n", 26, "Interface type",
	    lldp_mgmt_addr_substr(addr->iftype));
	(void) printf("%*s: %u\n", 26, "Interface number", addr->ifnum);
	(void) printf("%*s: %s\n", 26, "Address type",
	    iana_afstr(addr->addr_type));
	(void) lldp_addr_str(str, sizeof (str), addr->addr, addr->addr_len);
	(void) printf("%*s: %s\n", 26, "Address", str);
	if (addr->oid.len == 0)
		return;
	(void) printf("%*s: ", 26, "OID");
	for (i = 0; i < addr->oid.len; i++) {
		if (i > 0)
			fputc('.', stdout);
		(void) printf("%hhd", addr->oid.data[i]);
	}
	(void) fputc('\n', stdout);
}

static void
lldp_dump_nb_text(lldp_link_t *link, const lldp_neighbor_t *nb)
{
	lldp_mgmt_addr_t *addr;
	char str[256];
	int i;

	(void) printf("Link: %s\n", dlpi_linkname(link->dlh));
	fmt_macaddr(str, sizeof (str), nb->src, nb->srclen);
	(void) printf("                  From: %s\n", str);
	fmt_macaddr(str, sizeof (str), nb->dest, nb->destlen);
	(void) printf("                    To: %s\n", str);
	(void) strftime(str, sizeof (str) - 1, "%F %T%z", localtime(&nb->time));
	(void) printf("               Recv at: %s\n", str);
	(void) printf("                   TTL: %hhds%s\n",
	    nb->ttl, (nb->ttl == 0) ? " (shutdown)" : "");
	lldp_chassis_str(str, sizeof (str), nb->chassis_subtype,
	    nb->chassis_id, nb->chassis_len);
	(void) printf("            Chassis ID: %s (%s)\n", str,
	    lldp_chassis_substr(nb->chassis_subtype));
	lldp_port_str(str, sizeof (str), nb->port_subtype, nb->port_id,
	    nb->port_len);
	(void) printf("               Port ID: %s (%s)\n", str,
	    lldp_port_substr(nb->port_subtype));
	if (nb->port_desc != NULL)
		(void) printf("      Port description: %s\n", nb->port_desc);
	if (nb->sysname != NULL)
		(void) printf("           System name: %s\n", nb->sysname);
	if (nb->sysdesc != NULL)
		(void) printf("    System description: %s\n", nb->sysdesc);
	if (nb->cap != 0) {
		(void) lldp_cap_str(str, sizeof (str), nb->cap);
		(void) printf("   System capabilities: %#hhx<%s>\n",
		    nb->cap, str);
		(void) lldp_cap_str(str, sizeof (str), nb->en_cap);
		(void) printf("  Enabled capabilities: %#hhx<%s>\n",
		    nb->en_cap, str);
	}

	for (addr = MADDR_FIRST(nb);
	    addr != NULL;
	    addr = MADDR_NEXT(nb, addr))
		lldp_dump_mgmtaddr(addr);
}

static void
lldp_json_keyval(const char *key, boolean_t more, int indent,
    const char *fmt, ...)
{
	va_list ap;

	(void) printf("%*s\"%s\": ", indent, "", key);
	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
	if (more)
		(void) fputc(',', stdout);
	(void) fputc('\n', stdout);
}

static void
lldp_dump_nb_json(lldp_link_t *link, const lldp_neighbor_t *nb, int indent)
{
	lldp_mgmt_addr_t *addr, *next;
	char str[256];

	(void) printf("%*s\"%s\": {\n", indent, "", dlpi_linkname(link->dlh));
	indent += 4;

	fmt_macaddr(str, sizeof (str), nb->src, nb->srclen);
	lldp_json_keyval("from", B_TRUE, indent, "\"%s\"", str);

	fmt_macaddr(str, sizeof (str), nb->dest, nb->destlen);
	lldp_json_keyval("to", B_TRUE, indent, "\"%s\"", str);

	(void) strftime(str, sizeof (str) - 1, "%F %T%z", localtime(&nb->time));
	lldp_json_keyval("time", B_TRUE, indent, "\"%s\"", str);

	lldp_json_keyval("ttl", B_TRUE, indent, "\"%hd\"", nb->ttl);

	lldp_json_keyval("chassis type", B_TRUE, indent, "\"%s\"",
	    lldp_chassis_substr(nb->chassis_subtype));
	lldp_chassis_str(str, sizeof (str), nb->chassis_subtype,
	    nb->chassis_id, nb->chassis_len);
	lldp_json_keyval("chassis id", B_TRUE, indent, "\"%s\"", str);

	lldp_json_keyval("port type", B_TRUE, indent, "\"%s\"",
	    lldp_port_substr(nb->port_subtype));
	lldp_port_str(str, sizeof (str), nb->port_subtype, nb->port_id,
	    nb->port_len);
	lldp_json_keyval("port id", B_TRUE, indent, "\"%s\"", str);

	if (nb->port_desc != NULL)
		lldp_json_keyval("port description", B_TRUE, indent, "\"%s\"",
		    nb->port_desc);

	/* XXX: system capabilities */

	if (nb->sysname != NULL)
		lldp_json_keyval("system name", B_TRUE, indent, "\"%s\"",
		    nb->sysname);
	if (nb->sysdesc != NULL)
		lldp_json_keyval("system description",
		    (list_is_empty(&nb->mgmt_addrs)) ? B_FALSE : B_TRUE,
		    indent, "\"%s\"", nb->sysdesc);

	if (!list_is_empty(&nb->mgmt_addrs)) {
		lldp_json_keyval("management addresses", B_FALSE, indent, "[");
		indent += 4;

		addr = MADDR_FIRST(nb);
		while (addr != NULL) {
			next = MADDR_NEXT(nb, addr);

			(void) printf("%*s{\n", indent, "");
			indent += 4;
			lldp_json_keyval("interface type", B_TRUE, indent,
			    "\"%s\"", "");
			lldp_json_keyval("interface number", B_TRUE, indent,
			    "\"%u\"", addr->ifnum);
			lldp_json_keyval("address type", B_TRUE, indent,
			    "\"%s\"", iana_afstr(addr->addr_type));

			(void) lldp_addr_str(str, sizeof (str), addr->addr,
			    addr->addr_len);
			lldp_json_keyval("address",
			    (addr->oid.len != 0) ? B_TRUE : B_FALSE, indent,
			    "\"%s\"", str);

			if (addr->oid.len != 0) {
				int i;

				(void) printf("%*s\"oid\": \"", indent, "");
				for (i = 0; i < addr->oid.len; i++) {
					if (i != 0)
						fputc('.', stdout);
					(void) printf("%hhu",
					    addr->oid.data[i]);
				}
				(void) printf("\"\n");
			}
			indent -= 4;
			(void) printf("%*s}", indent, "");
			if (next != NULL)
				(void) fputc(',', stdout);
			(void) fputc('\n', stdout);

			addr = next;
		}
		indent -= 4;
		fputc(']', stdout);
		fputc('\n', stdout);
	}

	indent -= 4;
	(void) printf("%*s}\n", indent, "");
}

static void
lldp_dump_neighbor(lldp_link_t *link, const lldp_neighbor_t *nb)
{
	if (nb == NULL)
		return;

	flockfile(stdout);

	if (json)
		lldp_dump_nb_json(link, nb, 0);
	else
		lldp_dump_nb_text(link, nb);

	funlockfile(stdout);
}
