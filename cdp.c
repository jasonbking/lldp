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
#include <sys/pfmod.h>
#include <pthread.h>
#include <umem.h>
#include <note.h>
#include <err.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stropts.h>
#include <errno.h>
#include <port.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/ethernet.h>
#include "lldd.h"
#include "list.h"
#include "cdp.h"

#define	CDP_VERSION_1 1
#define	CDP_VERSION_2 2

typedef enum cdp_addr_proto_e {
	CDP_PROTO_NLPID = 1,
	CDP_PROTO_802_2
} cdp_addr_proto_t;

typedef enum cdp_tlv_e {
	CDP_TLV_DEVICE_ID = 1,
	CDP_TLV_ADDRESS,
	CDP_TLV_PORT_ID,
	CDP_TLV_CAPABILITIES,
	CDP_TLV_VERSION,
	CDP_TLV_PLATFORM,
	CDP_TLV_IP_PREFIX,
	CDP_TLV_VTP_MGMT_DOMAIN,
	CDP_TLV_NATIVE_VLAN,
	CDP_TLV_DUPLEX,
	CDP_TLV_LOCATION
} cdp_tlv_t;
#define	CDP_TLV_HDR_LEN 4

#define	CDP_CAP_ROUTER		((uint32_t)1 << 0)
#define	CDP_CAP_TBRIDGE		((uint32_t)1 << 1)
#define	CDP_CAP_SBRIDGE		((uint32_t)1 << 2)
#define	CDP_CAP_SWITCH		((uint32_t)1 << 3)
#define	CDP_CAP_HOST		((uint32_t)1 << 4)
#define	CDP_CAP_IGMP		((uint32_t)1 << 5)
#define	CDP_CAP_REPEATER	((uint32_t)1 << 6)

typedef struct cdp_worker_s {
	pthread_t	tid;
	int		port;

	list_t		links;
	list_t		nb_by_expire;

	buf_t		pdu;
	size_t		pdu_alloc;

	hrtime_t	next_tx;
} cdp_worker_t;
#define	LINK_FIRST (cdp_link_t *)list_head(&cdp_worker->links)
#define	LINK_NEXT(l) (cdp_link_t *)list_next(&cdp_worker->links, (void *)(l))

struct cdp_link_s;
typedef struct cdp_nb_s {
	struct cdp_link_s	*link;

	list_node_t		node_link;
	list_node_t		node_expire;

	hrtime_t		expire;
	time_t			when;

	uint8_t			cdp_version;
	uint8_t			ttl;

	uint8_t			src[DLPI_PHYSADDR_MAX];
	size_t			srclen;

	uint8_t			dest[DLPI_PHYSADDR_MAX];
	size_t			destlen;

	char			*id;

	struct sockaddr_storage	*addrs;
	size_t			num_addrs;

	char			*port_id;
	uint32_t		capabilities;
	char			*version;
	char			*platform;
	char			*vtp_mgmt_domain;

	in_addr_t		default_gw;
	in_prefix_t		*ip_prefix;
	size_t			num_prefix;

	char			*location;
	uint16_t		native_vlan;
	uint8_t			duplex;
#define	HAS_DUPLEX
} cdp_nb_t;

typedef struct cdp_link_s {
	link_t		*link;
	cdp_worker_t	*worker;

	list_node_t	node;

	char		*name;	/* overrides link name if set */
	dlpi_handle_t	dlh;
	dlpi_notifyid_t	dl_nid;
	uint_t		mtu;
	boolean_t	enabled;
	boolean_t	tx;
	boolean_t	rx;

	list_t		neighbors;
} cdp_link_t;

static uint8_t cdp_addr[] = "\x01\x00\x0c\xcc\xcc\xcc";

static uint64_t cdp_tx_interval;
static uint8_t cdp_ttl = 180;

static char cdp_platform[256];
static uint32_t cdp_cap;
static struct sockaddr_storage *cdp_addrs;
static size_t cdp_num_addrs;

static cdp_worker_t **cdp_workers;
static size_t cdp_num_workers;
static __thread cdp_worker_t *cdp_worker;
static umem_cache_t *cdp_nb_cache;

static const char *cdp_capstr[] = {
	"router", "transparent bridge", "source route bridge", "switch",
	"host", "IGMP", "repeater"
};

static cdp_nb_t *cdp_nb_alloc(void);
static void cdp_nb_free(cdp_nb_t *);
static const char *cdp_tlv_str(cdp_tlv_t);

static void
cdp_schedule(cdp_link_t *link)
{
	int rc;

	/* go through link so we can do this from any thread */
	rc = port_associate(link->worker->port, PORT_SOURCE_FD,
	    dlpi_fd(link->dlh), POLLIN, (void *)link);
	if (rc != 0)
		DMSG(D_NET, "cdp: port_associate(%s) failed: %s",
		    dlpi_linkname(link->dlh), strerror(errno));
}

static void
cdp_set_size(size_t len)
{
	uint8_t *temp;

	if (cdp_worker->pdu_alloc >= len)
		return;

	temp = realloc(cdp_worker->pdu.data, len);
	if (temp == NULL)
		return;

	cdp_worker->pdu.data = temp;
	cdp_worker->pdu.len = cdp_worker->pdu_alloc = len;
}

static boolean_t
cdp_get_string(cdp_tlv_t type, buf_t *val, char **str)
{
	*str = calloc(1, val->len + 1);
	if (*str == NULL)
		return (B_FALSE);

	getmem(val, *str, val->len);

	DMSG(D_PARSE, "cdp: %s = %s", cdp_tlv_str(type), *str);

	return (B_TRUE);
}

/*
 * If someone was really bored, they could expand this list
 */
static struct cdp_proto_s {
	uint8_t		proto[8];
	size_t		len;
	sa_family_t	af;
} cdp_proto_map[] = {
	{ "\xcc", 1, AF_INET },
	{ "\xaa\xaa\x03\x00\x00\x00\x08\x00", 8, AF_INET },
	{ "\x00\x80\x00", 3, AF_INET },
	{ "\xaa\xaa\x03\x00\x00\x00\x86\xdd", 8, AF_INET6 },
	{ "\x00\x86\xdd", 3, AF_INET6 }
};

/* XXX: add type checking */

static sa_family_t
cdp_get_addr_family(const uint8_t *buf, size_t len)
{
	int i;

	for (i = 0;
	    i < sizeof (cdp_proto_map) / sizeof (struct cdp_proto_s);
	    i++) {
		if (cdp_proto_map[i].len != len)
			continue;
		if (memcmp(cdp_proto_map[i].proto, buf, len) == 0)
			return (cdp_proto_map[i].af);
	}
	return (AF_UNSPEC);
}

static boolean_t
cdp_get_address(buf_t *val, cdp_nb_t *nb)
{
	cdp_addr_proto_t type;
	uint8_t proto[8];
	uint8_t proto_len;
	uint16_t addr_len;
	int i;

	if (val->len < sizeof (uint32_t)) {
		/* XXX: msg */
		return (B_FALSE);
	}

	nb->num_addrs = get32(val);
	nb->addrs = calloc(nb->num_addrs, sizeof (struct sockaddr_storage));
	if (nb->addrs == NULL) {
		/* XXX: msg */
		nb->num_addrs = 0;
		return (B_FALSE);
	}

	i = 0;
	while (i < nb->num_addrs && val->len > 1) {
		struct sockaddr_in *in = (struct sockaddr_in *)&nb->addrs[i];
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&nb->addrs[i];

		type = get8(val);
		proto_len = get8(val);

		if (proto_len > val->len) {
			/* XXX: msg */
			free(nb->addrs);
			nb->num_addrs = 0;
			return (B_FALSE);
		}

		/* skip it if the length doesn't look right */
		if (proto_len != 1 && proto_len != 3 && proto_len != 8) {
			BUF_ADD(val, proto_len);
			if (val->len < sizeof (uint16_t)) {
				/* XXX: msg */
				break;
			}
			addr_len = get16(val);
			if (addr_len > val->len) {
				/* XXX: msg */
				break;
			}
			BUF_ADD(val, addr_len);

			/*
			 * don't increment i so we only include the addresses
			 * we can handle
			 */
			continue;
		}

		nb->addrs[i].ss_family = cdp_get_addr_family(proto, proto_len);

		if (val->len < sizeof (uint16_t)) {
			/* XXX: msg */
			break;
		}

		addr_len = get16(val);
		if (val->len < addr_len) {
			/* XXX: msg */
			break;
		}

		switch (nb->addrs[i].ss_family) {
		case AF_INET:
			if (addr_len != sizeof (in_addr_t)) {
				BUF_ADD(val, addr_len);
				break;
			}
			(void) getmem(val, &in->sin_addr, addr_len);
			break;
		case AF_INET6:
			if (addr_len != sizeof (in6_addr_t)) {
				BUF_ADD(val, addr_len);
				break;
			}
			(void) getmem(val, &in6->sin6_addr, addr_len);
			break;
		default:
			BUF_ADD(val, addr_len);
		}

		i++;
	}

	if (i == 0) {
		nb->num_addrs = 0;
		free(nb->addrs);
		nb->addrs = NULL;
		return (B_TRUE);
	}

	/* had a few we need to skip */
	if (i != nb->num_addrs) {
		nb->addrs = realloc(nb->addrs,
		    i * sizeof (struct sockaddr_storage));
		nb->num_addrs = i;
	}

	return (B_TRUE);
}

static boolean_t
cdp_get_ip_prefix(buf_t *val, cdp_nb_t *nb)
{
	int i;

	/* this is a default gateway, not an IP prefix */
	if (val->len == sizeof (in_addr_t)) {
		char str[INET_ADDRSTRLEN];

		nb->default_gw = get32(val);
		DMSG(D_PARSE, "cdp: default gateway = %s",
		    inet_ntop(AF_INET, &nb->default_gw, str, sizeof (str)));

		return (B_TRUE);
	}

	nb->num_prefix = val->len / 5;
	if ((val->len % 5) != 0) {
		nb->num_prefix = 0;
		DMSG(D_PARSE, "cdp: IP prefix length (%zu) is invalid",
		    val->len);
		return (B_FALSE);
	}

	nb->ip_prefix = calloc(nb->num_prefix, sizeof (in_prefix_t));
	if (nb->ip_prefix == NULL) {
		DMSG(D_PARSE, "cdp: no memory for IP prefix");
		nb->num_prefix = 0;
		return (B_FALSE);
	}
	getmem(val, nb->ip_prefix, val->len);

	for (i = 0; i < nb->num_prefix; i++) {
		char str[INET_ADDRSTRLEN];

		DMSG(D_PARSE, "cdp: ip prefix = %s/%u",
		    inet_ntop(AF_INET, &nb->ip_prefix[i].in_prefix_addr, str,
		    sizeof (str)), nb->ip_prefix[i].in_prefix_len);
	}
	return (B_TRUE);
}

static void
cdp_parse(cdp_link_t *link, const uint8_t *src, size_t srclen,
    const uint8_t *dest, size_t destlen)
{
	cdp_nb_t *nb;
	buf_t buf;
	uint16_t cksum;

	BUF_DUP(&buf, &cdp_worker->pdu);

	nb = cdp_nb_alloc();
	if (nb == NULL) {
		DMSG(D_PARSE, "cdp: no memory for neighbor");
		return;
	}

	nb->link = link;
	nb->when = time(NULL);
	(void) memcpy(nb->src, src, srclen);
	(void) memcpy(nb->dest, dest, destlen);

	if (buf.len < 4) {
		DMSG(D_PARSE, "cdp: PDU is truncated");
		cdp_nb_free(nb);
		return;
	}

	nb->cdp_version = get8(&buf);
	DMSG(D_PARSE, "cdp: cdp version = %hhu", nb->cdp_version);

	nb->ttl = get8(&buf);
	DMSG(D_PARSE, "cdp: ttl = %hhus", nb->ttl);

	nb->expire = gethrtime() + (hrtime_t)nb->ttl * NANOSEC;
	cksum = get16(&buf);
	DMSG(D_PARSE, "cdp: checksum = %#04hx", cksum);

	while (buf.len > 0) {
		cdp_tlv_t type;
		uint16_t len;
		buf_t val;
		boolean_t ok = B_TRUE;

		if (buf.len < 4) {
			DMSG(D_PARSE, "cdp: PDU is truncated");
			break;
		}
		type = get16(&buf);
		len = get16(&buf);

		DMSG(D_PARSE, "cdp: type = %d (%s)", type, cdp_tlv_str(type));
		DMSG(D_PARSE, "cdp: length = %'hu bytes", len);

		if (len > buf.len) {
			DMSG(D_PARSE, "cdp: TLV length exceeds PDU length");
			cdp_nb_free(nb);
			return;
		}

		val.data = buf.data;
		/* TLV length includes header length */
		val.len = len - 2 * sizeof (uint16_t);

		switch (type) {
		case CDP_TLV_DEVICE_ID:
			ok = cdp_get_string(type, &val, &nb->id);
			break;
		case CDP_TLV_ADDRESS:
			ok = cdp_get_address(&val, nb);
			break;
		case CDP_TLV_PORT_ID:
			ok = cdp_get_string(type, &val, &nb->port_id);
			break;
		case CDP_TLV_CAPABILITIES:
			if (val.len != sizeof (uint32_t)) {
				DMSG(D_PARSE, "cdp: capabilities TLV length "
				    "mismatch");
				break;
			}
			nb->capabilities = get32(&val);
			break;
		case CDP_TLV_VERSION:
			ok = cdp_get_string(type, &val, &nb->version);
			break;
		case CDP_TLV_PLATFORM:
			ok = cdp_get_string(type, &val, &nb->platform);
			break;
		case CDP_TLV_IP_PREFIX:
			ok = cdp_get_ip_prefix(&val, nb);
			break;
		case CDP_TLV_VTP_MGMT_DOMAIN:
			ok = cdp_get_string(type, &val, &nb->vtp_mgmt_domain);
			break;
		case CDP_TLV_NATIVE_VLAN:
			if (val.len != sizeof (uint16_t)) {
				DMSG(D_PARSE, "cdp: native vlan TLV length "
				    "mismatch");
				break;
			}
			nb->native_vlan = get16(&val);
			break;
		case CDP_TLV_DUPLEX:
			break;
		case CDP_TLV_LOCATION:
			ok = cdp_get_string(type, &val, &nb->version);
			break;

		default:
			/* just ignore */
			break;
		}

		if (!ok) {
			cdp_nb_free(nb);
			return;
		}

		BUF_ADD(&buf, len);
	}

	/* XXX save */
}

static void
cdp_rx(cdp_link_t *link)
{
	char str[DLPI_PHYSADDR_MAX * 3];
	uint8_t src[DLPI_PHYSADDR_MAX];
	size_t srclen;
	dlpi_recvinfo_t ri;
	int rc, len;

	if (!link->rx || !link->enabled)
		goto drain;

	/* XXX: # neighbor check */

	rc = ioctl(dlpi_fd(link->dlh), I_NREAD, &len);
	if (rc == -1) {
		DMSG(D_NET|D_CDP, "cdp: ioctl(%s, I_NREAD) failed: %s",
		    dlpi_linkname(link->dlh), strerror(errno));
		goto drain;
	}

	if (len == 0)
		goto drain;

	cdp_set_size(len);

	srclen = sizeof (src);
	cdp_worker->pdu.len = cdp_worker->pdu_alloc;

	rc = dlpi_recv(link->dlh, src, &srclen, cdp_worker->pdu.data,
	    &cdp_worker->pdu.len, -1, &ri);
	fmt_macaddr(str, sizeof (str), ri.dri_destaddr, ri.dri_destaddrlen);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_CDP, "cdp: dlpi_recv(%s) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
		return;
	}
	DMSG(D_NET|D_CDP, "cdp: %s: received a %'zu byte PDU from %s",
	    dlpi_linkname(link->dlh), ri.dri_totmsglen, str);

	if (ri.dri_totmsglen > cdp_worker->pdu_alloc) {
		DMSG(D_NET|D_CDP, "cdp: dlpi_recv(%s) message "
		    "was too large (%'zu bytes).", dlpi_linkname(link->dlh),
		    ri.dri_totmsglen);
		return;
	}

	cdp_parse(link, src, srclen, ri.dri_destaddr, ri.dri_destaddrlen);
	return;

drain:
	rc = dlpi_recv(link->dlh, NULL, NULL, NULL, NULL, 0, NULL);
	if (rc != DLPI_SUCCESS)
		DMSG(D_NET|D_CDP, "cdp: dlpi_recv(%s) (drain) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
}

static boolean_t
cdp_put_hdr(buf_t *buf, cdp_tlv_t type, size_t len)
{
	if (buf->len < CDP_TLV_HDR_LEN)
		return (B_FALSE);

	put16(buf, type);
	put16(buf, len);

	return (B_TRUE);
}

static boolean_t
cdp_add_string(buf_t *buf, cdp_tlv_t type, const char *str)
{
	size_t len = strlen(str);
	size_t outlen;

	outlen = MIN(len + CDP_TLV_HDR_LEN, buf->len);

	if (!cdp_put_hdr(buf, type, outlen))
		return (B_FALSE);

	outlen -= CDP_TLV_HDR_LEN;
	if (!putmem(buf, str, outlen))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Based off RFC1071
 */
static uint16_t
cdp_cksum(buf_t *buf)
{
	uint8_t *p = buf->data;
	size_t len = buf->len;
	uint64_t sum = 0;
	int i;

	while (len > sizeof (uint32_t) - 1) {
		sum += *(uint32_t *)p;
		p += sizeof (uint32_t);
		len -= sizeof (uint32_t);
	}

	for (i = 0; i < len; i++)
		sum += *p++;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (~sum);
}


static ssize_t
cdp_make_pdu(cdp_link_t *link)
{
	buf_t buf;
	uint16_t *cksum;

	buf.data = cdp_worker->pdu.data;
	buf.len = cdp_worker->pdu_alloc;
	cksum = (uint16_t *)&buf.data[2];

	if (buf.len < 4)
		return (-1);

	(void) memset(buf.data, 0, buf.len);

	put8(&buf, CDP_VERSION_2);	/* Version */
	put8(&buf, cdp_ttl);		/* TTL */
	put16(&buf, 0);			/* checksum (set later) */

	if (!cdp_add_string(&buf, CDP_TLV_DEVICE_ID, hostname))
		goto done;
	/* XXX: address */
	if (!cdp_add_string(&buf, CDP_TLV_PORT_ID,
	    (link->name != NULL) ? link->name : dlpi_linkname(link->dlh)))
		goto done;
	/* XXX: capabilities */
	if (!cdp_add_string(&buf, CDP_TLV_VERSION, host_description))
		goto done;
	if (!cdp_add_string(&buf, CDP_TLV_PLATFORM, cdp_platform))
		goto done;
	/* XXX: ip prefix */

done:
	cdp_worker->pdu.len = cdp_worker->pdu_alloc - buf.len;
	*cksum = cdp_cksum(&cdp_worker->pdu);
	return (cdp_worker->pdu.len);
}

static void
cdp_send(cdp_link_t *link, ssize_t len)
{
	int rc;

	DMSG(D_CDP|D_NET, "cdp: %s sending %'zd byte PDU",
	    dlpi_linkname(link->dlh), len);

	rc = dlpi_send(link->dlh, cdp_addr, sizeof (cdp_addr),
	    cdp_worker->pdu.data, len, NULL);

	if (rc != DLPI_SUCCESS)
		DMSG(D_CDP|D_NET, "cdp: dlpi_send(%s) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
}

static void
cdp_tx(void)
{
	cdp_link_t *link;

	for (link = LINK_FIRST; link != NULL; link = LINK_NEXT(link)) {
		ssize_t len;

		if (!link->tx)
			continue;

		if ((len = cdp_make_pdu(link)) == -1)
			continue;

		cdp_send(link, len);
	}
	cdp_worker->next_tx = gethrtime() + (hrtime_t)cdp_tx_interval * NANOSEC;
}

static void *
cdp_loop(void *data)
{
	boolean_t quit = B_FALSE;

	cdp_worker = (cdp_worker_t *)data;

	DMSG(D_THREAD|D_CDP, "cdp: %s enter", __func__);

	while (!quit) {
		cdp_link_t *link;
		hrtime_t delta;
		timespec_t timeout;
		port_event_t pe;
		int rc;

		delta = cdp_worker->next_tx - gethrtime();
		if (delta > 0) {
			timeout.tv_sec = delta / NANOSEC;
			timeout.tv_nsec = delta % NANOSEC;
		} else {
			cdp_tx();
			continue;
		}

		rc = port_get(cdp_worker->port, &pe, &timeout);
		if (rc != 0) {
			if (errno == ETIME) {
				DMSG(D_CDP|D_TIMER, "cdp: tx timer expired");
				cdp_tx();
				continue;
			}
			DMSG(D_CDP, "cdp: port_get(%d) failed: %s",
			    cdp_worker->port, strerror(errno));
			continue;
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_FD:
			link = (cdp_link_t *)pe.portev_source;
			cdp_rx(link);
			cdp_schedule(link);
			continue;
		case PORT_SOURCE_ALERT:
			switch (pe.portev_events) {
			/* XXX: TODO */
			case 0:
				break;
			}
			break;
		case PORT_SOURCE_USER:
			switch (pe.portev_events) {
			/* XXX: TODO */
			case 0:
				break;
			}
		default:
			VERIFY(0);
		}
	}

	return (NULL);
}

static void
cdp_dlpi_notify(dlpi_handle_t dlh, dlpi_notifyinfo_t *ni, void *arg)
{
	cdp_link_t *link = (cdp_link_t *)arg;

	switch (ni->dni_note) {
	case DL_NOTE_LINK_DOWN:
		link->enabled = B_FALSE;
		DMSG(D_NET|D_CDP, "cdp: link down on %s", dlpi_linkname(dlh));
		break;

	case DL_NOTE_LINK_UP:
		link->enabled = B_TRUE;
		DMSG(D_NET|D_CDP, "cdp: link up on %s", dlpi_linkname(dlh));
		break;

	case DL_NOTE_SDU_SIZE:
		link->mtu = ni->dni_size;
		DMSG(D_NET|D_CDP, "cdp: MTU size changed on %s to %'zu bytes",
		    dlpi_linkname(dlh), link->mtu);
		break;

	case DL_NOTE_SPEED:
	case DL_NOTE_PHYS_ADDR:
		break;

	default:
		DMSG(D_NET|D_CDP, "cdp: unknown DLPI notification %u received "
		    "on %s", ni->dni_note, dlpi_linkname(dlh));
	}
}

static boolean_t
cdp_open(cdp_link_t *link)
{
	struct packetfilt pf;
	struct strioctl ioc;
	ushort_t *fp = pf.Pf_Filter;
	uint_t notes;
	int rc;

	DMSG(D_NET|D_CDP, "cdp: opening %s", link->link->name);

	rc = dlpi_open(link->link->name, &link->dlh, DLPI_PASSIVE);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_LLDP, "cdp: dlpi_open(%s) failed: %s",
		    link->link->name, dlpi_strerror(rc));
		return (B_FALSE);
	}

	DMSG(D_NET, "cdp: %s DLPI fd is %d", dlpi_linkname(link->dlh),
	    dlpi_fd(link->dlh));

	rc = dlpi_enabmulti(link->dlh, cdp_addr, ETHERADDRL);
	if (rc != DLPI_SUCCESS) {
		char str[DLPI_PHYSADDR_MAX * 3];

		fmt_macaddr(str, sizeof (str), cdp_addr, sizeof (cdp_addr));
		DMSG(D_NET|D_CDP, "cdp: dlpi_enabmilti(%s, %s) failed: %s",
		    dlpi_linkname(link->dlh), str, dlpi_strerror(rc));
		dlpi_close(link->dlh);
		link->dlh = NULL;
		return (B_FALSE);
	}

	rc = dlpi_bind(link->dlh, DLPI_ANY_SAP, NULL);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_CDP, "cdp: dlpi_bind(%s, DLPI_ANY_SAP) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
		dlpi_close(link->dlh);
		link->dlh = NULL;
		return (B_FALSE);
	}

	notes = DL_NOTE_PHYS_ADDR | DL_NOTE_LINK_DOWN | DL_NOTE_LINK_UP |
	    DL_NOTE_SDU_SIZE | DL_NOTE_SPEED;

	rc = dlpi_enabnotify(link->dlh, notes, cdp_dlpi_notify, (void *)link,
	    &link->dl_nid);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET|D_CDP, "cdp: dlpi_enabnotify(%s) failed: %s",
		    dlpi_linkname(link->dlh), dlpi_strerror(rc));
		dlpi_close(link->dlh);
		link->dlh = NULL;
		return (B_FALSE);
	}

	rc = ioctl(dlpi_fd(link->dlh), I_PUSH, "pfmod");
	if (rc != 0) {
		DMSG(D_NET|D_CDP, "cdp: ioctl(%s, I_PUSH, pfmod) failed: %s",
		    dlpi_linkname(link->dlh), strerror(errno));
		dlpi_close(link->dlh);
		link->dlh = NULL;
		return (B_FALSE);
	}

	/*
	 * CDP uses SNAP-encapsulated frames, so we have to listen on all
	 * SAPs and use pfmod to select only the CDP frames.
	 *
	 * CDP uses an OUI of 0x00000C and a protocol ID of 0x2000
	 *
	 * The comparison is a bit ouf of order of the bytes to faclitiate
	 * discarding unwanted packets as quick as possible.
	 */
	*fp++ = ENF_PUSHWORD + 3;	/* validate protocol ID is CDP */
	*fp++ = ENF_PUSHLIT | ENF_CAND;
	*fp++ = htons(0x2000);

	*fp++ = ENF_PUSHWORD + 0;	/* validate DSAP & SSAP are SNAP */
	*fp++ = ENF_PUSHLIT | ENF_CAND;
	*fp++ = htons(0xaaaa);

	*fp++ = ENF_PUSHWORD + 1;	/* validate OUI is Cisco (0x00000c) */
	*fp++ = ENF_PUSH00FF | ENF_AND; /* discard upper bit */
	*fp++ = ENF_PUSHZERO | ENF_CAND;
	*fp++ = ENF_PUSHWORD + 2;
	*fp++ = ENF_PUSHLIT | ENF_CAND;
	*fp++ = htons(0x000c);

	pf.Pf_FilterLen = fp - &pf.Pf_Filter[0];

	ioc.ic_cmd = PFIOCSETF;
	ioc.ic_timout = -1;
	ioc.ic_len = sizeof (pf);
	ioc.ic_dp = (char *)&pf;

	rc = ioctl(dlpi_fd(link->dlh), I_STR, &ioc);
	if (rc != 0) {
		DMSG(D_NET|D_CDP, "cdp: ioctl(%s, I_STR, cdp_filter) failed: "
		    "%s", dlpi_linkname(link->dlh), strerror(errno));
		dlpi_close(link->dlh);
		link->dlh = NULL;
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * for now at least, we consider two CDP neighbors identical if
 * the src addresses, system id, and port id are the same.
 */

static int
cdp_nb_cmp(const cdp_nb_t *n1, const cdp_nb_t *n2)
{
	int rc;

	if (n1->srclen != n2->srclen)
		return ((n1->srclen < n2->srclen) ? -1 : 1);
	if ((rc = memcmp(n1->src, n2->src, n1->srclen)) != 0)
		return (rc);
	if ((rc = strcmp(n1->id, n2->id)) != 0)
		return (rc);
	return (strcmp(n1->port_id, n2->port_id));
}

static cdp_nb_t *
cdp_find_nb(cdp_link_t *link, const cdp_nb_t *nb)
{
	cdp_nb_t *next;
	for (next = list_head(&link->neighbors);
	    next != NULL;
	    next = list_next(&link->neighbors, next)) {
		int rc = cdp_nb_cmp(next, nb);

		if (rc == 0)
			return (next);

		if (rc > 0)
			return (NULL);
	}
	return (NULL);
}

static void
cdp_add_nb(cdp_link_t *link, cdp_nb_t *nb)
{
	cdp_nb_t *next;

	next = cdp_find_nb(link, nb);
	if (next != NULL) {
		ASSERT(list_link_active(&next->node_expire));
		list_remove(&cdp_worker->nb_by_expire, next);
		list_link_replace(&next->node_link, &nb->node_link);
		cdp_nb_free(next);
		next = NULL;
	}

	for (next = list_head(&cdp_worker->nb_by_expire);
	    next != NULL;
	    next = list_next(&cdp_worker->nb_by_expire, next)) {
		if (next->expire > nb->expire)
			break;
	}
	list_insert_before(&cdp_worker->nb_by_expire, next, nb);

	if (list_link_active(&nb->node_link))
		return;

	for (next = list_head(&link->neighbors);
	    next != NULL;
	    next = list_next(&link->neighbors, next)) {
		int rc = cdp_nb_cmp(next, nb);

		if (rc > 0)
			break;
	}
	list_insert_before(&link->neighbors, next, nb);
}

static boolean_t
cdp_read_config(void)
{
	return (B_TRUE);
}

static cdp_link_t *
cdp_link_alloc(link_t *lld)
{
	cdp_link_t *link = calloc(1, sizeof (cdp_link_t));

	if (link == NULL)
		return (NULL);

	link->link = lld;
	list_create(&link->neighbors, sizeof (cdp_nb_t),
	    offsetof (cdp_nb_t, node_link));

	return (link);
}

static cdp_nb_t *
cdp_nb_alloc(void)
{
	return ((cdp_nb_t *)umem_cache_alloc(cdp_nb_cache, UMEM_DEFAULT));
}

static void
cdp_nb_free(cdp_nb_t *nb)
{
	if (nb == NULL)
		return;

	if (list_link_active(&nb->node_link))
		list_remove(&nb->link->neighbors, (void *)nb);
	if (list_link_active(&nb->node_expire))
		list_remove(&cdp_worker->nb_by_expire, (void *)nb);

	free(nb->id);
	free(nb->addrs);
	free(nb->port_id);
	free(nb->version);
	free(nb->platform);
	free(nb->ip_prefix);
	free(nb->location);
	free(nb->vtp_mgmt_domain);

	(void) memset(nb, 0, sizeof (cdp_nb_t));
	umem_cache_free(cdp_nb_cache, nb);
}

static int
cdp_nb_ctor(void *buf, void *cb, int flags)
{
	NOTE(ARGUNUSED(cb))
	NOTE(ARGUNUSED(flags))

	(void) memset(buf, 0, sizeof (cdp_nb_t));
	return (0);
}

void
cdp_init(int numworkers)
{
	link_t *lld;
	int i, rc;

	cdp_nb_cache = umem_cache_create("cdp neighbors", sizeof (cdp_nb_t),
	    8, cdp_nb_ctor, NULL, NULL, NULL, NULL, 0);
	if (cdp_nb_cache == NULL)
		errx(EXIT_FAILURE, "unable to create CDP object caches");

	if (!cdp_read_config())
		errx(EXIT_FAILURE, "unable to read configuration");

	cdp_workers = calloc(numworkers, sizeof (cdp_worker_t *));
	if (cdp_workers == NULL)
		err(EXIT_FAILURE, "calloc");

	for (i = 0; i < numworkers; i++) {
		cdp_worker_t *worker = malloc(sizeof (cdp_worker_t));

		if (worker == NULL)
			err(EXIT_FAILURE, "malloc");

		worker->port = port_create();
		if (worker->port == -1)
			err(EXIT_FAILURE, "port_create");

		worker->pdu.data = malloc(1500);
		if (worker->pdu.data == NULL)
			err(EXIT_FAILURE, "malloc");
		worker->pdu.len = 1500;
		worker->pdu_alloc = 1500;

		list_create(&worker->links, sizeof (cdp_link_t),
		    offsetof(cdp_link_t, node));
		list_create(&worker->nb_by_expire, sizeof (cdp_nb_t),
		    offsetof(cdp_nb_t, node_expire));

		cdp_workers[i] = worker;
	}

	lld = (link_t *)list_head(&links);
	i = 0;
	while (lld != NULL) {
		cdp_worker_t *worker;
		cdp_link_t *link;

		link = cdp_link_alloc(lld);
		if (link == NULL)
			err(EXIT_FAILURE, "cdp_link_alloc");
		if (!cdp_open(link))
			err(EXIT_FAILURE, "unable to open %s", lld->name);
		worker = link->worker = cdp_workers[i++ % numworkers];
		list_insert_tail(&worker->links, link);

		cdp_schedule(link);
		lld = (link_t *)list_next(&links, lld);
	}

	for (i = 0; i < numworkers; i++) {
		rc = pthread_create(&cdp_workers[i]->tid, NULL, cdp_loop,
		    cdp_workers[i]);
		if (rc != 0)
			errx(EXIT_FAILURE, "pthread_create(): %s",
			    strerror(rc));
	}
}

static const char *
cdp_tlv_str(cdp_tlv_t type)
{
	switch (type) {
	case CDP_TLV_DEVICE_ID:
		return ("device id");
	case CDP_TLV_ADDRESS:
		return ("address");
	case CDP_TLV_PORT_ID:
		return ("port id");
	case CDP_TLV_CAPABILITIES:
		return ("capabilities");
	case CDP_TLV_VERSION:
		return ("system version");
	case CDP_TLV_PLATFORM:
		return ("system platform");
	case CDP_TLV_IP_PREFIX:
		return ("ip prefix");
	case CDP_TLV_VTP_MGMT_DOMAIN:
		return ("vtp management domain");
	case CDP_TLV_NATIVE_VLAN:
		return ("native vlan");
	case CDP_TLV_DUPLEX:
		return ("duplex");
	case CDP_TLV_LOCATION:
		return ("location");
	default:
		return ("unknown");
	}
}
