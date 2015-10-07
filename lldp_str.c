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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "lldd.h"
#include "lldp.h"
#include "lldp_int.h"

static const char *capstr[] = {
	LLDP_CAPSTR_OTHER,
	LLDP_CAPSTR_REPEATER,
	LLDP_CAPSTR_MAC_BRIDGE,
	LLDP_CAPSTR_AP,
	LLDP_CAPSTR_ROUTER,
	LLDP_CAPSTR_PHONE,
	LLDP_CAPSTR_DOCSIS,
	LLDP_CAPSTR_STATION,
	LLDP_CAPSTR_CVLAN,
	LLDP_CAPSTR_SVLAN,
	LLDP_CAPSTR_TPMR
};

/*
 * Convert an LLDP-style 'address family + address" string into
 * a presentable address
 */
size_t
lldp_addr_str(char *str, size_t len, const uint8_t *addr, size_t addrlen)
{
	(void) memset(str, 0, len);

	switch (addr[0]) {
	case IANA_IPV4:
		(void) inet_ntop(AF_INET, &addr[1], str, len);
		return (INET_ADDRSTRLEN + 1);
	case IANA_IPV6:
		(void) inet_ntop(AF_INET6, &addr[1], str, len);
		return (INET6_ADDRSTRLEN + 1);
	default:
		return (fmt_macaddr(str, len, addr, addrlen));
	}
}

const char *
lldp_tlv_str(lldp_tlv_t type)
{
	switch (type) {
	case LLDP_TLV_END:
		return ("end");
	case LLDP_TLV_CHASSIS_ID:
		return ("chassis id");
	case LLDP_TLV_PORT_ID:
		return ("port id");
	case LLDP_TLV_TTL:
		return ("ttl");
	case LLDP_TLV_PORT_DESC:
		return ("port description");
	case LLDP_TLV_SYSNAME:
		return ("system name");
	case LLDP_TLV_SYSDESC:
		return ("system description");
	case LLDP_TLV_SYSCAP:
		return ("system capabilities");
	case LLDP_TLV_MGMTADDR:
		return ("management address");
	case LLDP_TLV_ORG:
		return ("organizational specific");
	default:
		return ("unknown");
	}
}

size_t
lldp_cap_str(char *buf, size_t len, uint16_t val)
{
	const char *p;
	size_t bit;
	boolean_t first;

	if (len == 0)
		return (0);

	buf[0] = '\0';
	for (bit = 0, first = B_TRUE;
	    bit < sizeof (capstr) / sizeof (char *);
	    bit++) {
		if (!(val & _BIT(bit)))
			continue;

		(void) strlcat(buf, capstr[bit], len);
		if (!first)
			(void) strlcat(buf, ",", len);
		first = B_FALSE;
	}

	return (0);
}

size_t
lldp_chassis_str(char *str, size_t len, lldp_chassis_id_t type,
    const uint8_t *id, size_t idlen)
{
	if (len == 0)
		return (0);

	switch (type) {
	case LLDP_CHASSIS_COMPONENT:
	case LLDP_CHASSIS_IFALIAS:
	case LLDP_CHASSIS_PORT:
	case LLDP_CHASSIS_IFNAME:
	case LLDP_CHASSIS_LOCAL: {
		/* guarantee we don't overrun + NULL terminate */
		size_t copylen = (idlen < len - 1) ? idlen : len - 1;

		(void) memcpy(str, id, copylen);
		str[copylen] = '\0';
		return (copylen + 1);
	}
	case LLDP_CHASSIS_NETADDR:
		return (lldp_addr_str(str, len, id, idlen));
	case LLDP_CHASSIS_MACADDR:
	default:
		return (fmt_macaddr(str, len, id, idlen));
	}
}

size_t
lldp_port_str(char *str, size_t len, lldp_port_id_t type, const uint8_t *id,
    size_t idlen)
{
	if (len == 0)
		return (0);

	switch (type) {
	case LLDP_PORT_IFALIAS:
	case LLDP_PORT_COMPONENT:
	case LLDP_PORT_IFNAME:
	case LLDP_PORT_LOCAL: {
		size_t copylen = (idlen < len - 1) ? idlen : len - 1;

		(void) memcpy(str, id, copylen);
		str[copylen] = '\0';
		return (copylen + 1);
	}
	case LLDP_PORT_NETADDR:
		return (lldp_addr_str(str, len, id, idlen));
	case LLDP_PORT_CIRCUIT_ID: {
		/* construct a long hex humber */
		size_t outlen = 2 + idlen * 2 + 1;
		int i;

		str[0] = '\0';
		(void) strlcat(str, "0x", len);
		for (i = 0; i < idlen; i++) {
			char buf[3];

			(void) snprintf(buf, sizeof (buf), "%02hhx", id[i]);
			(void) strlcat(str, buf, len);
		}
		return (outlen);
	}
	case LLDP_PORT_MACADDR:
	default:
		return (fmt_macaddr(str, len, id, idlen));
	}
}

const char *
lldp_chassis_substr(lldp_chassis_id_t type)
{
	switch (type) {
	case LLDP_CHASSIS_COMPONENT:
		return ("chassis component");
	case LLDP_CHASSIS_IFALIAS:
		return ("interface alias");
	case LLDP_CHASSIS_PORT:
		return ("port component");
	case LLDP_CHASSIS_MACADDR:
		return ("mac address");
	case LLDP_CHASSIS_NETADDR:
		return ("network address");
	case LLDP_CHASSIS_IFNAME:
		return ("interface name");
	case LLDP_CHASSIS_LOCAL:
		return ("locally assigned");
	default:
		return ("unknown");
	}
}

const char *
lldp_port_substr(lldp_port_id_t type)
{
	switch (type) {
	case LLDP_PORT_IFALIAS:
		return ("interface alias");
	case LLDP_PORT_COMPONENT:
		return ("port component");
	case LLDP_PORT_MACADDR:
		return ("mac address");
	case LLDP_PORT_NETADDR:
		return ("network address");
	case LLDP_PORT_IFNAME:
		return ("interface name");
	case LLDP_PORT_CIRCUIT_ID:
		return ("circuit id");
	case LLDP_PORT_LOCAL:
		return ("locally assigned");
	default:
		return ("unknown");
	}
}

#define	STR(_x) \
	case _x: \
		return (#_x)

const char *
lldp_tx_statestr(lldp_tx_state_t state)
{
	switch (state) {
	STR(TX_BEGIN);
	STR(TX_LLDP_INITIALIZE);
	STR(TX_IDLE);
	STR(TX_SHUTDOWN_FRAME);
	STR(TX_INFO_FRAME);
	default:
		return ("UNKNOWN");
	}
}

const char *
lldp_rx_statestr(lldp_rx_state_t state)
{
	switch (state) {
	STR(RX_BEGIN);
	STR(LLDP_WAIT_PORT_OPERATIONAL);
	STR(DELETE_AGED_INFO);
	STR(RX_LLDP_INITIALIZE);
	STR(RX_WAIT_FOR_FRAME);
	STR(RX_FRAME);
	STR(DELETE_INFO);
	STR(UPDATE_INFO);
	default:
		return ("UNKNOWN");
	}
}

const char *
lldp_timer_statestr(lldp_timer_state_t state)
{
	switch (state) {
	STR(TIMER_BEGIN);
	STR(TX_TIMER_INITIALIZE);
	STR(TX_TIMER_IDLE);
	STR(TX_TIMER_EXPIRES);
	STR(TX_TICK);
	STR(SIGNAL_TX);
	STR(TX_FAST_START);
	default:
		return ("UNKNOWN");
	}
}

const char *
lldp_status_str(lldp_admin_status_t status)
{
	switch (status) {
	case LLDP_LINK_TX:
		return ("enabled TX");
	case LLDP_LINK_RX:
		return ("enabled RX");
	case LLDP_LINK_TXRX:
		return ("enabled TXRX");
	case LLDP_LINK_DISABLED:
		return ("disabled");
	default:
		return ("unknown");
	}
}
