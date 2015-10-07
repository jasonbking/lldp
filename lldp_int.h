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

#ifndef _LLDP_INT_H
#define	_LLDP_INT_H

#include <sys/types.h>
#include <libdlpi.h>
#include "lldd.h"
#include "lldp.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum lldp_tlv_e {
	LLDP_TLV_END,
	LLDP_TLV_CHASSIS_ID,
	LLDP_TLV_PORT_ID,
	LLDP_TLV_TTL,
	LLDP_TLV_PORT_DESC,
	LLDP_TLV_SYSNAME,
	LLDP_TLV_SYSDESC,
	LLDP_TLV_SYSCAP,
	LLDP_TLV_MGMTADDR,
	LLDP_TLV_ORG = 127
} lldp_tlv_t;

typedef enum lldp_timer_id_e {
	LLDP_TIMER_TX,
	LLDP_TIMER_AGE,
	LLDP_TIMER_SHUTDOWN,
	LLDP_TIMER_MAX			/* must be last */
} lldp_timer_id_t;

typedef struct lldp_timer_t {
	list_node_t	node;
	hrtime_t	when;
} lldp_timer_t;

typedef struct lldp_mgmt_addr_s {
	list_node_t		list_node;

	iana_af_t		addr_type;
	uint8_t			addr_len;
	uint8_t			addr[LLDP_MGMT_ADDR_MADDR_MAX];
	lldp_mgmt_ifnum_t	iftype;
	uint32_t		ifnum;
	buf_t			oid;
} lldp_mgmt_addr_t;

struct lldp_neighbor_s;
struct lldp_link_s;
typedef struct lldp_neighbor_s {
	struct lldp_link_s	*link;

	time_t			time;

	lldp_timer_t		timer;
	uint16_t		ttl;

	uint8_t			src[DLPI_PHYSADDR_MAX];
	size_t			srclen;

	uint8_t			dest[DLPI_PHYSADDR_MAX];
	size_t			destlen;

	lldp_chassis_id_t	chassis_subtype;
	uint8_t			chassis_id[LLDP_CHASSIS_ID_MAX];
	size_t			chassis_len;

	lldp_port_id_t		port_subtype;
	uint8_t			port_id[LLDP_PORT_ID_MAX];
	size_t			port_len;

	char			*port_desc;
	char			*sysname;
	char			*sysdesc;
	uint16_t		cap;
	uint16_t		en_cap;

	list_t			mgmt_addrs;
} lldp_neighbor_t;
#define	MADDR_FIRST(nb) (lldp_mgmt_addr_t *)list_head(&(nb)->mgmt_addrs)
#define	MADDR_NEXT(nb, n) (lldp_mgmt_addr_t *)list_next(&(nb)->mgmt_addrs, (n))

typedef enum lldp_tx_state_e {
	TX_BEGIN,
	TX_LLDP_INITIALIZE,
	TX_IDLE,
	TX_SHUTDOWN_FRAME,
	TX_INFO_FRAME
} lldp_tx_state_t;

typedef enum lldp_timer_state_e {
	TIMER_BEGIN,
	TX_TIMER_INITIALIZE,
	TX_TIMER_IDLE,
	TX_TIMER_EXPIRES,
	SIGNAL_TX,
	TX_TICK,
	TX_FAST_START
} lldp_timer_state_t;

typedef enum lldp_rx_state_e {
	RX_BEGIN,
	LLDP_WAIT_PORT_OPERATIONAL,
	DELETE_AGED_INFO,
	RX_LLDP_INITIALIZE,
	RX_WAIT_FOR_FRAME,
	RX_FRAME,
	DELETE_INFO,
	UPDATE_INFO
} lldp_rx_state_t;

struct link_s;
struct lldp_worker_s;
typedef struct lldp_link_s {
	struct link_s		*lld;
	struct lldp_worker_s	*worker;

	list_node_t		list_by_worker;
	list_node_t		list_active;
	list_node_t		list_tick;

	lldp_timer_t		timers[LLDP_TIMER_MAX];
	hrtime_t		too_many;

	dlpi_handle_t		dlh;
	dlpi_notifyid_t		dl_nid;

	boolean_t		enabled;
	lldp_admin_status_t	admin_status;

	lldp_rx_state_t		rx_state;
	lldp_tx_state_t		tx_state;
	lldp_timer_state_t	timer_state;

	uint32_t		tx_credit;
	uint16_t		tx_ttl;
	uint16_t		rx_ttl;
	uint32_t		tx_fast;
	boolean_t		tx_now;
	boolean_t		rx_info_age;
	boolean_t		recv_frame;
	boolean_t		rx_changes;
	boolean_t		bad_frame;
	boolean_t		local_changes;
	boolean_t		new_neighbor;
	boolean_t		tx_tick;

	uint32_t		tx_tlv;
	uint32_t		tx_x1_tlv;
	uint32_t		tx_x3_tlv;

	lldp_port_id_t		port_subtype;
	uint8_t			port_id[LLDP_PORT_ID_MAX];
	char			*desc;
	uint16_t		mtu;

	list_t			neighbors;
	uint_t			num_neighbors;
	uint_t			max_neighbors;

	uint32_t		tx_frames;
	uint32_t		tx_toobig;

	uint32_t		rx_frames;
	uint32_t		rx_discarded;
	uint32_t		rx_errors;
	uint32_t		rx_recv;
	uint32_t		rx_tlv_discarded;
	uint32_t		rx_tlv_unknown;
	uint32_t		rx_ageouts;
} lldp_link_t;
#define	NB_FIRST(x)	(lldp_neighbor_t *)list_head(&(x)->neighbors)
#define	NB_LAST(x)	(lldp_neighbor_t *)list_tail(&(x)->neighbors)
#define	NB_NEXT(x, n) (lldp_neighbor_t *)list_next(&(x)->neighbors, \
	(void *)(n))
#define	NB_PREV(x, n) (lldp_neighbor_t *)list_prev(&(x)->neighbors, \
	(void *)(n))

typedef struct lldp_worker_s {
	pthread_t	tid;

	int		port;

	buf_t		pdu;
	size_t		pdu_alloc;

	uint8_t		src[DLPI_PHYSADDR_MAX];
	uint8_t		dest[DLPI_PHYSADDR_MAX];
	size_t		srclen;
	size_t		destlen;

	lldp_neighbor_t	*nb;

	list_t		links;
	list_t		active;

	list_t		tick;
	hrtime_t	tick_time;

	list_t		timers[LLDP_TIMER_MAX];
} lldp_worker_t;
#define	LINK_FIRST (lldp_link_t *)list_head(&lldp_worker->links)
#define	LINK_NEXT(l) (lldp_link_t *)list_next(&lldp_worker->links, (void *)(l))

#define	TICK_FIRST (lldp_link_t *)list_head(&lldp_worker->tick)
#define	TICK_NEXT(l) (lldp_link_t *)list_next(&lldp_worker->tick, (void *)(l))

extern __thread lldp_worker_t 	*lldp_worker;

extern lldp_chassis_id_t	lldp_chassis_type;
extern buf_t			lldp_chassis_id;
extern char			*lldp_sysname;
extern char			*lldp_sysdesc;
extern uint16_t			lldp_cap;
extern uint16_t			lldp_encap;
extern struct sockaddr_storage	*lldp_mgmt_addrs;
extern size_t			lldp_num_mgmt_addrs;

void lldp_set_size(size_t);
void lldp_process_frame(lldp_link_t *);
ssize_t lldp_create_pdu(lldp_link_t *, uint16_t);

/* lldp_timer.c */
int lldp_timer_val(lldp_link_t *, lldp_timer_id_t);
void lldp_set_tick(lldp_link_t *, boolean_t);
void lldp_set_timer(lldp_link_t *, lldp_timer_id_t, int);
void lldp_process_timers(void);
timespec_t *lldp_get_timeout(timespec_t *);

/* lldp.c */
void lldp_set_active(lldp_link_t *);
void lldp_run_active(void);

/* lldp_str.c */
const char *lldp_tlv_str(lldp_tlv_t);
const char *lldp_tx_statestr(lldp_tx_state_t);
const char *lldp_rx_statestr(lldp_rx_state_t);
const char *lldp_timer_statestr(lldp_timer_state_t);

/* lldp_obj.c */
void lldp_obj_init(void);

lldp_link_t *lldp_link_alloc(link_t *);
lldp_worker_t *lldp_worker_alloc(void);
lldp_neighbor_t *lldp_neighbor_alloc();
lldp_mgmt_addr_t *lldp_mgmt_addr_alloc(void);

void lldp_neighbor_add(lldp_link_t *, lldp_neighbor_t *);
int lldp_mgmt_addr_cmp(const lldp_mgmt_addr_t *, const lldp_mgmt_addr_t *);
void lldp_add_mgmt_addr(lldp_neighbor_t *, lldp_mgmt_addr_t *);

void lldp_worker_free(lldp_worker_t *);
void lldp_neighbor_free(lldp_neighbor_t *);
void lldp_mgmt_addr_free(lldp_mgmt_addr_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LLDP_INT_H */
