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
#include <sys/socket.h>
#include <string.h>
#include <note.h>
#include <unistd.h>
#include <libnvpair.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <umem.h>

#include "lldd.h"
#include "lldp.h"
#include "lldp_int.h"

#define	LLDP_HDR_LEN (sizeof (uint16_t))
#define	LLDP_TYPE(_tlv)	((lldp_tlv_t)(((_tlv) & 0xfe00) >> 9))
#define	LLDP_LEN(_tlv) ((_tlv) & 0x1ff)

#define	LLDP_HDR_VAL(_t, _l) \
	(((uint16_t)(_t) << 9) | ((uint16_t)(_l) & 0x1ff))
#define	PUT_TLV_HDR(buf, type, len)  put16((buf), LLDP_HDR_VAL((type), (len)))

#define	LLDP_ID_MIN 2
#define	LLDP_ID_MAX 256

#define	LLDP_MGMT_ADDR_MIN 9
#define	LLDP_MGMT_ADDR_MAX 167
#define	MGMT_ADDR_MIN 2
#define	MGMT_ADDR_MAX 32
#define	MGMT_OID_MAX 128

static boolean_t
lldp_get_tlv(buf_t *buf, lldp_tlv_t *type, buf_t *tlv)
{
	uint16_t hdr;

	if (buf->len < LLDP_HDR_LEN) {
		DMSG(D_PARSE, "lldp: attempted to read TLV header with only "
		    "%zu bytes left in PDU.", buf->len);
		return (B_FALSE);
	}

	hdr = get16(buf);
	*type = LLDP_TYPE(hdr);
	tlv->data = buf->data;
	tlv->len = (size_t)LLDP_LEN(hdr);

	DMSG(D_PARSE, "lldp: tlv type %d (%s) length: %'zu bytes", *type,
	    lldp_tlv_str(*type), tlv->len);

	return (B_TRUE);
}

static boolean_t
lldp_validate_netaddr(iana_af_t af, size_t len)
{
	if (len < 1)
		return (B_FALSE);
	switch (af) {
	case IANA_IPV4:
		if (len != INET_ADDRSTRLEN + 1)
			return (B_FALSE);
		break;
	case IANA_IPV6:
		if (len != INET6_ADDRSTRLEN + 1)
			return (B_FALSE);
		break;
	}
	return (B_TRUE);
}

static boolean_t
lldp_get_chassis_id(buf_t *tlv)
{
	lldp_neighbor_t *nb = lldp_worker->nb;

	if (tlv->len < 2) {
		DMSG(D_PARSE, "lldp: %s: tlv length is below "
		    "minimum required size (2 bytes).", __func__);
		return (B_FALSE);
	}

	nb->chassis_subtype = get8(tlv);
	DMSG(D_PARSE, "lldp: chassis subtype: %d %s",
	    nb->chassis_subtype,
	    lldp_chassis_substr(nb->chassis_subtype));

	if (tlv->len > LLDP_CHASSIS_ID_MAX) {
		DMSG(D_PARSE, "lldp: %s: chassis id length exceeds maximum "
		    "allowed amount (%zd bytes).", __func__,
		    LLDP_CHASSIS_ID_MAX);
		return (B_FALSE);
	}

	nb->chassis_len = tlv->len;

	if (nb->chassis_subtype == LLDP_CHASSIS_NETADDR &&
	    !lldp_validate_netaddr(tlv->data[0], tlv->len - 1)) {
		DMSG(D_PARSE, "lldp: network address length (%zu bytes) "
		    "is incorrect for %s address family", tlv->len - 1,
		    iana_afstr(tlv->data[0]));
		return (B_FALSE);
	}

	(void) memcpy(nb->chassis_id, tlv->data, tlv->len);
	if (dlevel & D_PARSE) {
		char str[LLDP_CHASSIS_ID_MAX + 1];

		(void) lldp_chassis_str(str, sizeof (str),
		    nb->chassis_subtype,
		    nb->chassis_id,
		    nb->chassis_len);
		DMSG(D_PARSE, "lldp: chassis id: %s", str);
	}

	return (B_TRUE);
}

static boolean_t
lldp_get_port_id(buf_t *tlv)
{
	lldp_neighbor_t *nb = lldp_worker->nb;

	if (tlv->len < 2) {
		DMSG(D_PARSE, "lldp: %s: tlv length is below minimum required "
		    "size (2 bytes).", __func__);
		return (B_FALSE);
	}

	nb->port_subtype = get8(tlv);
	DMSG(D_PARSE, "lldp: port subtype: %d %s",
	    nb->port_subtype, lldp_port_substr(nb->port_subtype));

	if (tlv->len > LLDP_PORT_ID_MAX) {
		DMSG(D_PARSE, "lldp: %s: port id length exceeds maximum "
		    "allowed amount (%zd bytes).", __func__,
		    LLDP_PORT_ID_MAX);
		return (B_FALSE);
	}

	nb->port_len = tlv->len;

	if (nb->port_subtype == LLDP_PORT_NETADDR &&
	    !lldp_validate_netaddr(tlv->data[0], tlv->len - 1)) {
		DMSG(D_PARSE, "lldp: network address length (%zu bytes) "
		    "is incorrect for %s address family", tlv->len - 1,
		    iana_afstr(tlv->data[0]));
		return (B_FALSE);
	}

	(void) memcpy(nb->port_id, tlv->data, tlv->len);
	if (dlevel & D_PARSE) {
		char str[LLDP_PORT_ID_MAX + 1];

		(void) lldp_port_str(str, sizeof (str),
		    nb->port_subtype, nb->port_id, nb->port_len);
		DMSG(D_PARSE, "lldp: port id: %s", str);
	}

	return (B_TRUE);
}

static boolean_t
lldp_get_ttl(buf_t *tlv)
{
	lldp_neighbor_t *nb = lldp_worker->nb;

	if (tlv->len < sizeof (uint16_t)) {
		DMSG(D_PARSE, "lldp: TTL tlv is below minimum allowed size "
		    "(2 bytes).");
		return (B_FALSE);
	}

	if ((nb->ttl = get16(tlv)) > 0)
		nb->timer.when = gethrtime() + (hrtime_t)nb->ttl * NANOSEC;
	else
		nb->timer.when = 0;

	if (dlevel & D_PARSE) {
		char str[16];

		if (nb->ttl > 0)
			(void) interval_str(str, sizeof (str), nb->ttl);
		else
			strlcpy(str, "shutdown", sizeof (str));

		DMSG(D_PARSE, "lldp: ttl: %'hus (%s)", nb->ttl, str);
	}

	/*
	 * 9.2.7.7.1 -- anything in the TTL TLV beyond the first 2 bytes
	 * is ignored.  We just note it.
	 */
	if (tlv->len > 0)
		DMSG(D_LLDP, "TTL tlv contains %'zu bytes of trailing data.",
		    tlv->len);

	return (B_TRUE);
}

static boolean_t
lldp_get_mandatory_tlv(buf_t *buf, lldp_tlv_t expected)
{
	const char *which = NULL;
	boolean_t (*fn)(buf_t *);
	lldp_tlv_t type;
	buf_t tlv;

	if (!lldp_get_tlv(buf, &type, &tlv))
		return (B_FALSE);

	switch (expected) {
	case LLDP_TLV_CHASSIS_ID:
		which = "first";
		fn = lldp_get_chassis_id;
		break;
	case LLDP_TLV_PORT_ID:
		which = "second";
		fn = lldp_get_port_id;
		break;
	case LLDP_TLV_TTL:
		which = "third";
		fn = lldp_get_ttl;
		break;
	default:
		VERIFY(0);
	}

	if (type != expected) {
		DMSG(D_PARSE, "lldp: %s tlv is not %s; discarding PDU", which,
		    lldp_tlv_str(expected));
		return (B_FALSE);
	}

	if (tlv.len > buf->len) {
		DMSG(D_PARSE, "lldp: %s tlv extends beyond end of PDU; "
		    "discarding PDU", lldp_tlv_str(expected));
		return (B_FALSE);
	}

	BUF_ADD(buf, tlv.len);

	return (fn(&tlv));
}

static boolean_t
lldp_get_string(lldp_tlv_t type, buf_t *tlv, char **str)
{
	*str = calloc(1, tlv->len + 1);

	if (*str == NULL)
		return (B_FALSE);
	(void) memcpy(*str, tlv->data, tlv->len);
	DMSG(D_PARSE, "lldp:  %s: %s", lldp_tlv_str(type), *str);
	return (B_TRUE);
}

static boolean_t
lldp_get_cap(lldp_link_t *link, buf_t *buf)
{
	lldp_neighbor_t *nb = lldp_worker->nb;

	if (buf->len != 2 * sizeof (uint16_t)) {
		DMSG(D_PARSE, "lldp: invalid system capabilities tlv "
		    "length %'zu, expected 4", buf->len);
		link->bad_frame = B_TRUE;
		return (B_FALSE);
	}

	nb->cap = get16(buf);
	nb->en_cap = get16(buf);
	if (dlevel & D_PARSE) {
		char str[256];

		(void) lldp_cap_str(str, sizeof (str), nb->cap);
		DMSG(D_PARSE, "lldp:  system capabilities: %#04hx<%s>",
		    nb->cap, str);

		(void) lldp_cap_str(str, sizeof (str), nb->en_cap);
		DMSG(D_PARSE, "lldp: enabled capabilities: %#04hx<%s>",
		    nb->en_cap, str);
	}

	/*
	 * 802.1AB-2009 8.5.8.3 - dicard the TLV if the system
	 * shows something enabled that it doesn't also list as
	 * supported.
	 */
	if ((nb->cap | nb->en_cap) != nb->cap) {
		char str[256];
		uint16_t mismatch = (nb->cap ^ nb->en_cap) & nb->en_cap;

		(void) lldp_cap_str(str, sizeof (str), mismatch);

		DMSG(D_PARSE, "lldp: system capabilities tlv contains "
		    "enabled capabilities that are not also marked as "
		    "supported:\n"
		    "    %s\n", str);
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
lldp_get_mgmtaddr(lldp_link_t *link, buf_t *buf)
{
	lldp_mgmt_addr_t *maddr = NULL;

	if (buf->len < LLDP_MGMT_ADDR_MIN)
		goto truncated;

	if (buf->len > LLDP_MGMT_ADDR_MAX) {
		DMSG(D_PARSE, "lldp: management address tlv length "
		    "(%'zu bytes) exceeds maximum allowable length "
		    "(%d bytes).", buf->len, LLDP_MGMT_ADDR_MAX);
		return (B_FALSE);
	}

	maddr = lldp_mgmt_addr_alloc();
	if (maddr == NULL) {
		/* XXX: too many */
		return (B_FALSE);
	}

	maddr->addr_len = get8(buf);
	if (maddr->addr_len < MGMT_ADDR_MIN)
		goto truncated;
	if (maddr->addr_len > MGMT_ADDR_MAX) {
		DMSG(D_PARSE, "lldp: management address length (%'u bytes) "
		    "is greater than the allowed maximum (%d bytes).",
		    maddr->addr_len, MGMT_ADDR_MAX);
		lldp_mgmt_addr_free(maddr);
		return (B_FALSE);
	}
	if (maddr->addr_len > buf->len) {
		DMSG(D_PARSE, "lldp: management address string length (%u) "
		    "exceeds TLV length.", maddr->addr_len);
		link->bad_frame = B_TRUE;
		lldp_mgmt_addr_free(maddr);
		return (B_FALSE);
	}

	getmem(buf, maddr->addr, maddr->addr_len);
	if (buf->len < 6)
		goto truncated;

	maddr->iftype = get8(buf);
	maddr->ifnum = get32(buf);
	maddr->oid.len = get8(buf);
	if (maddr->oid.len > MGMT_OID_MAX) {
		DMSG(D_PARSE, "lldp: management address tlv OID length "
		    "(%'u bytes) exceeds maximum allowed value (%d bytes).",
		    maddr->oid.len, MGMT_OID_MAX);
		link->bad_frame = B_TRUE;
		lldp_mgmt_addr_free(maddr);
		return (B_FALSE);
	}
	if (buf->len < maddr->oid.len)
		goto truncated;
	if (maddr->oid.len > buf->len) {
		DMSG(D_PARSE, "lldp: management address tlv OID extends "
		    "beyond end of tlv.");
		lldp_mgmt_addr_free(maddr);
		return (B_FALSE);
	}
	maddr->oid.data = malloc(maddr->oid.len);
	if (maddr->oid.data == NULL) {
		/* XXX: too many */
		lldp_mgmt_addr_free(maddr);
		return (B_FALSE);
	}
	getmem(buf, maddr->oid.data, maddr->oid.len);

	lldp_add_mgmt_addr(lldp_worker->nb, maddr);

	return (B_TRUE);

truncated:
	DMSG(D_PARSE, "lldp: management address tlv is truncated.");
	lldp_mgmt_addr_free(maddr);
	link->bad_frame = B_TRUE;
	return (B_FALSE);
}

static lldp_neighbor_t *
lldp_get_neighbor(lldp_link_t *link, lldp_neighbor_t *nb)
{
	lldp_neighbor_t *check;

	for (check = (lldp_neighbor_t *)list_head(&link->neighbors);
	    check != NULL;
	    check = (lldp_neighbor_t *)list_next(&link->neighbors, check)) {
		if (check->chassis_subtype != nb->chassis_subtype)
			continue;
		if (check->chassis_len != nb->chassis_len)
			continue;
		if (check->port_subtype != nb->port_subtype)
			continue;
		if (check->port_len != nb->port_len)
			continue;
		if (memcmp(check->chassis_id, nb->chassis_id,
		    nb->chassis_len) != 0)
			continue;
		if (memcmp(check->port_id, nb->port_id, nb->port_len) != 0)
			continue;
		return (check);
	}
	return (NULL);
}

static boolean_t
xstrcmp(const char *l, const char *r)
{
	if (l == NULL && r == NULL)
		return (B_TRUE);
	/* utilize short-circuit eval */
	if (l == NULL || r == NULL)
		return (B_FALSE);
	if (strcmp(l, r) == 0)
		return (B_TRUE);
	return (B_FALSE);
}

/*
 * Verify all the management addresses are identical between two
 * neighbors.  Utilize that the addresses are kept in sorted order
 * to reduce the number of comparisons required.
 */
static boolean_t
lldp_cmp_addrs(lldp_neighbor_t *lnb, lldp_neighbor_t *rnb)
{
	lldp_mgmt_addr_t *l, *r;

	if (lnb == NULL && rnb == NULL)
		return (B_TRUE);
	if (lnb == NULL || rnb == NULL)
		return (B_FALSE);

	l = MADDR_FIRST(lnb);
	r = MADDR_FIRST(rnb);
	while (l != NULL && r != NULL) {
		if (lldp_mgmt_addr_cmp(l, r) != 0)
			return (B_FALSE);
		l = MADDR_NEXT(lnb, l);
		r = MADDR_NEXT(rnb, r);
	}

	if (l != NULL || r != NULL)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
lldp_same(lldp_neighbor_t *l, lldp_neighbor_t *r)
{
	if (l == NULL && r == NULL)
		return (B_TRUE);
	if (l == NULL || r == NULL)
		return (B_FALSE);
	if (l->cap != r->cap || l->en_cap != r->en_cap)
		return (B_FALSE);
	if (!xstrcmp(l->port_desc, r->port_desc))
		return (B_FALSE);
	if (!xstrcmp(l->sysname, r->sysname))
		return (B_FALSE);
	if (!xstrcmp(l->sysdesc, r->sysdesc))
		return (B_FALSE);
	if (!lldp_cmp_addrs(l, r))
		return (B_FALSE);

	return (B_FALSE);
}

#define	LLDP_TLV_BIT(x)		((uint32_t)1 << (x))
#define	LLDP_DUP_ALLOWED	LLDP_TLV_BIT(LLDP_TLV_MGMTADDR)

#define	SEEN(_seen, _tlv) ((_seen) & LLDP_TLV_BIT(_tlv))
#define	ALLOW_DUP(_tlv)	((_tlv) & LLDP_DUP_ALLOWED)
void
lldp_process_frame(lldp_link_t *link)
{
	lldp_neighbor_t *nb, *current;
	lldp_tlv_t type;
	uint32_t seen = 0;
	buf_t *buf = &lldp_worker->pdu;
	buf_t tlv;

	ASSERT(lldp_worker->nb == NULL);

	lldp_worker->nb = nb = lldp_neighbor_alloc();

	if (nb == NULL)
		goto too_many;

	(void) memcpy(nb->src, lldp_worker->src, lldp_worker->srclen);
	(void) memcpy(nb->dest, lldp_worker->dest, lldp_worker->destlen);
	nb->srclen = lldp_worker->srclen;
	nb->destlen = lldp_worker->destlen;

	if (!lldp_get_mandatory_tlv(buf, LLDP_TLV_CHASSIS_ID))
		goto bad_frame;
	if (!lldp_get_mandatory_tlv(buf, LLDP_TLV_PORT_ID))
		goto bad_frame;
	if (!lldp_get_mandatory_tlv(buf, LLDP_TLV_TTL))
		goto bad_frame;

	do {
		boolean_t ok = B_TRUE;

		if (buf->len == 0)
			break;

		if (link->bad_frame)
			goto bad_frame;

		if (!lldp_get_tlv(buf, &type, &tlv))
			goto bad_frame;

		if (tlv.len > buf->len) {
			/*
			 * 9.2.7.7.2 - TLVs that extend past the
			 * end of frame are discarded (but not the whole
			 * PDU).
			 */
			DMSG(D_PARSE, "lldp: %s (%#02x) tlv extends beyond "
			    "end of PDU.", lldp_tlv_str(type), type);
			link->rx_tlv_discarded++;
			break;
		}

		BUF_ADD(buf, tlv.len);

		if (SEEN(seen, type) && !ALLOW_DUP(type)) {
			DMSG(D_PARSE, "lldp: duplicate %s tlv found; "
			    "discarding tlv", lldp_tlv_str(type));
			link->rx_tlv_discarded++;
			continue;
		}

		switch (type) {
		case LLDP_TLV_CHASSIS_ID:
		case LLDP_TLV_PORT_ID:
		case LLDP_TLV_TTL:
			DMSG(D_PARSE, "lldp: invalid PDU: %s tlv appears "
			    "multiple times.", lldp_tlv_str(type));
			link->bad_frame = B_TRUE;
			goto bad_frame;

		case LLDP_TLV_END:
			if (tlv.len != 0) {
				DMSG(D_PARSE, "lldp: invalid PDU: END tlv "
				    "has non-zero length %zu.", tlv.len);
				link->bad_frame = B_TRUE;
				goto bad_frame;
			}

			/*
			 * 9.2.7.7.2 - any information following
			 * an END OF LLDP PDU is ignored.
			 */
			if (buf->len > 0)
				DMSG(D_PARSE, "lldp: note: %'zu bytes of "
				    "trailing data in PDU", buf->len);
			break;

		case LLDP_TLV_PORT_DESC:
			ok = lldp_get_string(type, &tlv, &nb->port_desc);
			break;
		case LLDP_TLV_SYSNAME:
			ok = lldp_get_string(type, &tlv, &nb->sysname);
			break;
		case LLDP_TLV_SYSDESC:
			ok = lldp_get_string(type, &tlv, &nb->sysdesc);
			break;
		case LLDP_TLV_SYSCAP:
			ok = lldp_get_cap(link, &tlv);
			break;
		case LLDP_TLV_MGMTADDR:
			ok = lldp_get_mgmtaddr(link, &tlv);
			break;
		case LLDP_TLV_ORG:
			break;
		default:
			DMSG(D_PARSE, "lldp: unknown tlv %#02x; skipping.",
			    type);
			link->rx_tlv_unknown++;
		}

		if (type != LLDP_TLV_ORG)
			seen |= LLDP_TLV_BIT(type);

		if (!ok) {
			link->rx_tlv_discarded++;
			link->rx_errors++;
		}

	} while (type != LLDP_TLV_END);

	link->rx_ttl = nb->ttl;

	/*
	 * XXX: this can probably be simplified by replacing the existing
	 * neighbor with the new one and readjusting the aging timer list
	 * when an existing neighbor is found.
	 */
	if ((current = lldp_get_neighbor(link, nb)) == NULL) {
		link->new_neighbor = B_TRUE;
		link->rx_changes = B_TRUE;
		return;
	}

	list_remove(&link->neighbors, current);
	link->num_neighbors--;
	if ((link->rx_changes = lldp_same(current, nb))) {
		lldp_neighbor_free(current);
		return;
	}

	/*
	 * update TTL & expiration time of existing neighbor
	 * and reinsert into agelist at new spot
	 */
	current->time = nb->time;
	current->ttl = nb->ttl;
	current->timer.when = nb->timer.when;
	lldp_neighbor_add(link, current);
	link->num_neighbors++;

	lldp_neighbor_free(nb);
	lldp_worker->nb = NULL;
	return;

bad_frame:
	link->bad_frame = B_TRUE;
	link->rx_errors++;
	link->rx_discarded++;
	return;

too_many:
	link->too_many = gethrtime() + (hrtime_t)link->rx_ttl * NANOSEC;
	return;
}

static boolean_t
lldp_add_end(buf_t *buf)
{
	if (buf->len < LLDP_HDR_LEN)
		return (B_FALSE);
	VERIFY(PUT_TLV_HDR(buf, LLDP_TLV_END, 0));
	return (B_TRUE);
}

static boolean_t
lldp_add_chassis_id(buf_t *buf)
{
	size_t len;

	len = strlen(hostname);

	if (buf->len < LLDP_HDR_LEN + len + sizeof (uint8_t))
		return (B_FALSE);

	VERIFY(PUT_TLV_HDR(buf, LLDP_TLV_CHASSIS_ID, len));
	VERIFY(put8(buf, LLDP_CHASSIS_LOCAL));
	VERIFY(putmem(buf, hostname, len));
	return (B_TRUE);
}


static boolean_t
lldp_add_port_id(buf_t *buf, const char *name)
{
	size_t len;

	len = strlen(name);
	if (buf->len < LLDP_HDR_LEN + sizeof (uint8_t) + len)
		return (B_FALSE);

	VERIFY(PUT_TLV_HDR(buf, LLDP_TLV_PORT_ID, sizeof (uint8_t) + len));
	VERIFY(put8(buf, LLDP_PORT_IFNAME));
	VERIFY(putmem(buf, (void *)name, len));
	return (B_TRUE);
}

static boolean_t
lldp_add_ttl(buf_t *buf, uint16_t ttl)
{
	if (buf->len < LLDP_HDR_LEN + sizeof (uint16_t))
		return (B_FALSE);

	VERIFY(PUT_TLV_HDR(buf, LLDP_TLV_TTL, sizeof (uint16_t)));
	VERIFY(put16(buf, ttl));
	return (B_TRUE);
}

static boolean_t
lldp_add_cap(buf_t *buf)
{
	if (buf->len < LLDP_HDR_LEN + 2 * sizeof (uint16_t))
		return (B_FALSE);

	VERIFY(PUT_TLV_HDR(buf, LLDP_TLV_SYSCAP, 2 * sizeof (uint16_t)));
	VERIFY(put16(buf, lldp_cap));
	VERIFY(put16(buf, lldp_encap));
	return (B_TRUE);
}

static boolean_t
lldp_add_string(buf_t *buf, lldp_tlv_t type, const char *name)
{
	size_t len = 0;

	if (name == NULL)
		return (B_TRUE);
	len = strlen(name);
	if (buf->len < LLDP_HDR_LEN + len)
		return (B_FALSE);

	VERIFY(PUT_TLV_HDR(buf, type, len));
	VERIFY(putmem(buf, name, len));
	return (B_TRUE);
}

static boolean_t
lldp_add_mgmtaddr(buf_t *buf, struct sockaddr_storage *ss, uint32_t idx,
    buf_t *oid)
{
	struct sockaddr_in *in = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
	uint8_t *addrp;
	iana_af_t af;
	size_t len, tlv_len;

	switch (ss->ss_family) {
	case AF_INET:
		af = IANA_IPV4;
		addrp = (uint8_t *)&in->sin_addr;
		len = sizeof (in_addr_t);
		break;
	case AF_INET6:
		af = IANA_IPV6;
		addrp = (uint8_t *)&in6->sin6_addr;
		len = sizeof (in6_addr_t);
		break;
	default:
		VERIFY(0);
	}

	tlv_len = 1 + 1 + len + sizeof (idx) + 1 + oid->len;
	if (buf->len < tlv_len + LLDP_HDR_LEN)
		return (B_FALSE);

	VERIFY(PUT_TLV_HDR(buf, LLDP_TLV_MGMTADDR, tlv_len));
	VERIFY(put8(buf, len + 1));
	VERIFY(put8(buf, af));
	VERIFY(putmem(buf, addrp, len));
	VERIFY(put8(buf, LLDP_MGMT_IFINDEX));
	VERIFY(put32(buf, idx));
	VERIFY(put8(buf, oid->len));
	if (oid->len > 0)
		VERIFY(putmem(buf, oid->data, oid->len));

	return (B_TRUE);
}

static boolean_t
lldp_add_mgmtaddrs(buf_t *buf)
{
	int i;
	boolean_t ok = B_TRUE;
	buf_t oid;

	oid.data = NULL;
	oid.len = 0;

	/* XXX: need to get ifindex */
	for (i = 0; i < lldp_num_mgmt_addrs; i++)
		ok &= lldp_add_mgmtaddr(buf, &lldp_mgmt_addrs[i], 0, &oid);
	return (ok);
}

ssize_t
lldp_create_pdu(lldp_link_t *link, uint16_t ttl)
{
	buf_t buf;
	size_t mtu = link->lld->dlinfo.di_max_sdu;
	boolean_t ok = B_TRUE;

	lldp_set_size(mtu);
	buf.data = lldp_worker->pdu.data;
	buf.len = lldp_worker->pdu_alloc;

	/* reserve space for the END OF PDU tlv */
	buf.len -= 2;

	if (!lldp_add_chassis_id(&buf))
		return (-1);
	if (!lldp_add_port_id(&buf, dlpi_linkname(link->dlh)))
		return (-1);
	if (!lldp_add_ttl(&buf, ttl))
		return (-1);

	if (ttl == 0)
		goto done;

	if (link->tx_tlv & LLDP_TX_PORTDESC)
		ok &= lldp_add_string(&buf, LLDP_TLV_PORT_DESC, link->desc);
	if (link->tx_tlv & LLDP_TX_SYSNAME)
		ok &= lldp_add_string(&buf, LLDP_TLV_SYSNAME, hostname);
	if (link->tx_tlv & LLDP_TX_SYSDESC)
		ok &= lldp_add_string(&buf, LLDP_TLV_SYSDESC, host_description);
	if (link->tx_tlv & LLDP_TX_SYSCAP)
		ok &= lldp_add_cap(&buf);
	if (link->tx_tlv & LLDP_TX_MGMTADDR)
		ok &= lldp_add_mgmtaddrs(&buf);

	/* XXX: org specfic */

	if (!ok) {
		DMSG(D_PARSE, "Ran out of room adding TLVs.  Some TLVs "
		    "will not be transmitted.");
		link->tx_toobig++;
	}

done:
	buf.len += 2;
	VERIFY(lldp_add_end(&buf));
	return (lldp_worker->pdu_alloc - buf.len);
}
