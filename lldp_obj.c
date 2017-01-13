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

#include <umem.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stddef.h>
#include <sys/debug.h>
#include <port.h>
#include <unistd.h>
#include <note.h>
#include "list.h"
#include "lldp_int.h"

#define	INITIAL_PDU_SIZE 1500	/* typical ethernet MTU */

static umem_cache_t *lldp_nb_cache;
static umem_cache_t *lldp_maddr_cache;

lldp_worker_t *
lldp_worker_alloc(void)
{
	lldp_worker_t *worker = calloc(1, sizeof (lldp_worker_t));
	int i;

	if (worker == NULL)
		return (NULL);

	(void) memset(worker, 0, sizeof (lldp_worker_t));

	/*
	 * due to 0 being a valid fd, this should happen prior
	 * to any other initialization
	 */
	if ((worker->port = port_create()) == -1) {
		warn("port_create");
		lldp_worker_free(worker);
		return (NULL);
	}

	if ((worker->pdu.data = malloc(INITIAL_PDU_SIZE)) == NULL) {
		lldp_worker_free(worker);
		return (NULL);
	}
	worker->pdu.len = INITIAL_PDU_SIZE;
	worker->pdu_alloc = INITIAL_PDU_SIZE;

	list_create(&worker->links, sizeof (lldp_link_t),
	    offsetof(lldp_link_t, list_by_worker));
	list_create(&worker->tick, sizeof (lldp_link_t),
	    offsetof(lldp_link_t, list_tick));
	list_create(&worker->active, sizeof (lldp_link_t),
	    offsetof(lldp_link_t, list_active));

	for (i = 0; i < LLDP_TIMER_MAX; i++)
		list_create(&worker->timers[i], sizeof (lldp_link_t),
		    offsetof(lldp_link_t, timers[i].node));

	return (worker);
}

void
lldp_worker_free(lldp_worker_t *worker)
{
	if (worker->port >= 0)
		(void) close(worker->port);
	free(worker->pdu.data);
	free(worker);
}

lldp_link_t *
lldp_link_alloc(link_t *lld)
{
	lldp_link_t *link;

	link = calloc(1, sizeof (lldp_link_t));
	if (link == NULL)
		return (NULL);

	link->lld = lld;
	lld->lldp = link;

	link->tx_tlv = 0xffff;

	list_create(&link->neighbors, sizeof (lldp_neighbor_t),
	    offsetof(lldp_neighbor_t, timer.node));

	return (link);
}

void
lldp_link_free(lldp_link_t *link)
{
	if (link == NULL)
		return;

	if (link->lld != NULL)
		link->lld->lldp = NULL;

	/* XXX: free neigbors, unlink */

	free(link);
}

/*
 * Add neighbor to link, sorted by time until expiration
 */
void
lldp_neighbor_add(lldp_link_t *link, lldp_neighbor_t *nb)
{
	lldp_neighbor_t *prev;
	hrtime_t now = gethrtime();

	nb->link = link;

	if (nb->ttl == 0) {
		list_insert_head(&link->neighbors, (void *)nb);
		return;
	}

	for (prev = NB_LAST(link); prev != NULL; prev = NB_PREV(link, prev)) {
		if (prev->timer.when > nb->timer.when)
			break;
	}
	list_insert_after(&link->neighbors, (void *)prev, (void *)nb);

	/*
	 * if we ended up doing a head insert, we need to reset the
	 * aging timer to the new value.
	 */
	if (nb == NB_FIRST(link))
		lldp_set_timer(link, LLDP_TIMER_AGE, nb->ttl);
}

lldp_neighbor_t *
lldp_neighbor_alloc(void)
{
	lldp_neighbor_t *nb;

	nb = (lldp_neighbor_t *)umem_cache_alloc(lldp_nb_cache, UMEM_DEFAULT);
	if (nb == NULL)
		return (NULL);
	nb->time = time(NULL);
	return (nb);
}

void
lldp_neighbor_free(lldp_neighbor_t *nb)
{
	lldp_mgmt_addr_t *maddr, *maddr_next;

	if (nb == NULL)
		return;

	maddr = (lldp_mgmt_addr_t *)list_head(&nb->mgmt_addrs);
	while (maddr != NULL) {
		maddr_next = (lldp_mgmt_addr_t *)list_next(&nb->mgmt_addrs,
		    maddr);
		lldp_mgmt_addr_free(maddr);
		maddr = maddr_next;
	}

	if (list_link_active(&nb->timer.node))
		list_remove(&nb->link->neighbors, (void *)nb);

	(void) memset(nb, 0, sizeof (lldp_neighbor_t));

	list_create(&nb->mgmt_addrs, sizeof (lldp_mgmt_addr_t),
	    offsetof(lldp_mgmt_addr_t, list_node));

	umem_cache_free(lldp_nb_cache, nb);
}

/*
 * Provide a sorting order for management addresses.
 * Essentially, sort if interface type, number, address type, number, oid
 */
int
lldp_mgmt_addr_cmp(const lldp_mgmt_addr_t *l, const lldp_mgmt_addr_t *r)
{
	size_t len;
	int rc;

	if (l->iftype != r->iftype)
		return ((l->iftype < r->iftype) ? -1 : 1);

	if (l->ifnum != r->ifnum)
		return ((l->ifnum < r->ifnum) ? -1 : 1);

	if (l->addr_type != r->addr_type)
		return ((l->addr_type < r->addr_type) ? -1 : 1);

	if (l->addr_len != r->addr_len)
		return ((l->addr_len < r->addr_len) ? -1 : 1);

	if ((rc = memcmp(l->addr, r->addr, l->addr_len)) != 0)
		return (rc);

	if (l->oid.len != r->oid.len)
		return ((l->oid.len < r->oid.len) ? -1 : 1);

	if (l->oid.len == 0)
		return (0);

	return (memcmp(l->oid.data, r->oid.data, l->oid.len));
}

/*
 * Add a management address to neighbor.
 * Management are inserted in sorted order (based on lldp_mgmt_addr_cmp()
 * ordering.
 */
void
lldp_add_mgmt_addr(lldp_neighbor_t *nb, lldp_mgmt_addr_t *addr)
{
	lldp_mgmt_addr_t *next;

	next = (lldp_mgmt_addr_t *)list_head(&nb->mgmt_addrs);
	while (next != NULL) {
		if (lldp_mgmt_addr_cmp(next, addr) > 0)
			break;

		next = (lldp_mgmt_addr_t *)list_next(&nb->mgmt_addrs,
		    (void *)next);
	}

	list_insert_before(&nb->mgmt_addrs, next, addr);
}

lldp_mgmt_addr_t *
lldp_mgmt_addr_alloc(void)
{
	return ((lldp_mgmt_addr_t *)umem_cache_alloc(lldp_maddr_cache,
	    UMEM_DEFAULT));
}

void
lldp_mgmt_addr_free(lldp_mgmt_addr_t *addr)
{
	if (addr == NULL)
		return;
	free(addr->oid.data);

	(void) memset(addr, 0, sizeof (lldp_mgmt_addr_t));
	umem_cache_free(lldp_maddr_cache, addr);
}

static int
lldp_nb_ctor(void *buf, void *cb, int flags)
{
	NOTE(ARGUNUSED(cb))
	NOTE(ARGUNUSED(flags))

	lldp_neighbor_t *nb = (lldp_neighbor_t *)buf;

	(void) memset(buf, 0, sizeof (lldp_neighbor_t));
	list_create(&nb->mgmt_addrs, sizeof (lldp_mgmt_addr_t),
	    offsetof(lldp_mgmt_addr_t, list_node));

	return (0);
}

static int
lldp_maddr_ctor(void *buf, void *cb, int flags)
{
	NOTE(ARGUNUSED(cb))
	NOTE(ARGUNUSED(flags))

	(void) memset(buf, 0, sizeof (lldp_mgmt_addr_t));
	return (0);
}

void
lldp_obj_init(void)
{
	lldp_nb_cache = umem_cache_create("lldp neighbors",
	    sizeof (lldp_neighbor_t), 8, lldp_nb_ctor, NULL, NULL, NULL,
	    NULL, 0);
	lldp_maddr_cache = umem_cache_create("lldp management addrs",
	    sizeof (lldp_mgmt_addr_t), 8, lldp_maddr_ctor, NULL, NULL, NULL,
	    NULL, 0);

	if (lldp_nb_cache == NULL || lldp_maddr_cache == NULL)
		errx(EXIT_FAILURE, "unable to create lldp object caches");
}
