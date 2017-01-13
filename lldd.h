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

#ifndef	_LLDD_H
#define	_LLDD_H

#include <sys/types.h>
#include <pthread.h>
#include <locale.h>
#include <libscf.h>
#include <libdlpi.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum iana_af_e {
	IANA_RESERVED,
	IANA_IPV4,
	IANA_IPV6,
	IANA_NSAP,
	IANA_HDLC,
	IANA_BBN,
	IANA_802,
	IANA_E163,
	IANA_E164,
	IANA_F69,
	IANA_X121,
	IANA_IPX,
	IANA_APPLETALK,
	IANA_DECNET,
	IANA_VINES,
	IANA_E164_NSAP,
	IANA_DNS,
	IANA_DN,
	IANA_AS,
	IANA_XTP4,
	IANA_XTP6,
	IANA_XTP,
	IANA_WWPN,
	IANA_WWNN,
	IANA_GWID,
	IANA_AFI
} iana_af_t;
const char *iana_afstr(iana_af_t);

typedef enum main_msg_e {
	MM_STOP,
	MM_ADDWORKER,
	MM_DELWORKER,
	MM_ADDPORT,
	MM_DELPORT
} main_msg_t;
void notify_main_msg(main_msg_t, void *);

typedef struct buf_s {
	uint8_t	*data;
	uint_t	len;
} buf_t;
#define	BUF_DUP(_dst, _src) \
	(_dst)->data = (_src)->data, (_dst)->len = (_src)->len
#define	BUF_ADD(_dst, _len) \
	(_dst)->data += (_len), (_dst)->len -= (_len)

typedef struct nvl_list_s {
	nvlist_t **nvls;
	size_t nelem;
	size_t alloc;
} nvl_list_t;

const char *lookup_vlan(uint16_t);
const char *lookup_proto(buf_t *);

struct lldp_agent_s;
struct cdp_port_s;
struct link_s;

struct link_s {
	pthread_mutex_t		lock;

	list_node_t		node;

	char			*name;
	dlpi_info_t		dlinfo;

	struct lldp_link_s	*lldp;
	struct cdp_link_s	*cdp;
};
typedef struct link_s link_t;

typedef struct scf_cfg_s {
	const char	*name;
	scf_type_t	type;
	void		*val;
	size_t		max;
} scf_cfg_t;
void read_scf_proto_cfg(const char *, scf_cfg_t *);

extern list_t links;

extern char *hostname;
extern char *host_description;
extern char *os_name;
extern char *os_release;
extern char *os_version;

link_t *link_alloc(const char *);
void link_free(link_t *);
boolean_t link_add(link_t *, boolean_t);
void link_unlink(link_t *);
uint32_t link_hash(const char *);

void buf_dup(buf_t *, buf_t *);
uint8_t get8(buf_t *);
uint16_t get16(buf_t *);
uint32_t get32(buf_t *);
uint64_t get64(buf_t *);
void getmem(buf_t *, void *, size_t);

boolean_t put8(buf_t *, uint8_t);
boolean_t put16(buf_t *, uint16_t);
boolean_t put32(buf_t *, uint32_t);
boolean_t put64(buf_t *, uint64_t);
boolean_t putmem(buf_t *, const void *, size_t);

extern pid_t pid;

extern size_t link_max_len;
extern boolean_t json;
extern int dlevel;
extern FILE *debugf;
void dprintf(const char *, ...);

ssize_t interval_str(char *, size_t, uint_t);
size_t fmt_macaddr(char *, size_t, const uint8_t *, size_t);

#define	D_THREAD	(1U << 0)
#define	D_NET		(1U << 1)
#define	D_PARSE		(1U << 2)
#define	D_LLDP		(1U << 3)
#define	D_CDP		(1U << 4)
#define	D_STATE		(1U << 6)
#define	D_TIMER		(1U << 7)
#define	D_OP		(1U << 8)

#define	DMSG(lvl, ...) if ((lvl) & dlevel) dprintf(__VA_ARGS__)
#define	BOOLSTR(b) ((b) ? "B_TRUE" : "B_FALSE")

#define	ARRAY_SIZE(x)	(sizeof (x) / sizeof(x[0]))

#ifdef __cplusplus
}
#endif

#endif /* _LLDD_H */
