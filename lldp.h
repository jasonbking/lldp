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

#ifndef _LLDP_H
#define	_LLDP_H

#include <sys/types.h>
#include <libdlpi.h>
#include <libnvpair.h>
#include "lldd.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum lldp_ret_e {
	LLDP_RET_OK,
	LLDP_RET_NOMEM,
	LLDP_RET_DISCARD,
	LLDP_RET_BAD
} lldp_ret_t;

typedef enum lldp_admin_status_e {
	LLDP_LINK_UNKNOWN,
	LLDP_LINK_TX,
	LLDP_LINK_RX,
	LLDP_LINK_TXRX,
	LLDP_LINK_DISABLED
} lldp_admin_status_t;

/*
 * Chassis ID subtypes
 */
typedef enum lldp_chassis_id_e {
	LLDP_CHASSIS_COMPONENT = 1,
	LLDP_CHASSIS_IFALIAS,
	LLDP_CHASSIS_PORT,
	LLDP_CHASSIS_MACADDR,
	LLDP_CHASSIS_NETADDR,
	LLDP_CHASSIS_IFNAME,
	LLDP_CHASSIS_LOCAL
} lldp_chassis_id_t;
#define	LLDP_CHASSIS_ID_MAX 255

/*
 * Port ID subtypes
 */
typedef enum lldp_port_id_e {
	LLDP_PORT_IFALIAS = 1,
	LLDP_PORT_COMPONENT,
	LLDP_PORT_MACADDR,
	LLDP_PORT_NETADDR,
	LLDP_PORT_IFNAME,
	LLDP_PORT_CIRCUIT_ID,
	LLDP_PORT_LOCAL
} lldp_port_id_t;
#define	LLDP_PORT_ID_MAX 255

#define	LLDP_PORT_DESC_MAX 255
#define	LLDP_SYSNAME_MAX 255
#define	LLDP_SYSDESC_MAX 255
#define	LLDP_MGMT_ADDR_MADDR_MAX 31

/*
 * System capability bit values
 */
#define	_BIT(_x) ((uint16_t)1 << (_x))
#define	LLDP_CAP_OTHER		_BIT(0)
#define	LLDP_CAP_REPEATER	_BIT(1)
#define	LLDP_CAP_MAC_BRIDGE	_BIT(2)
#define	LLDP_CAP_AP		_BIT(3)
#define	LLDP_CAP_ROUTER		_BIT(4)
#define	LLDP_CAP_PHONE		_BIT(5)
#define	LLDP_CAP_DOCSIS		_BIT(6)
#define	LLDP_CAP_STATION	_BIT(7)
#define	LLDP_CAP_CVLAN		_BIT(8)
#define	LLDP_CAP_SVLAN		_BIT(9)
#define	LLDP_CAP_TPMR		_BIT(10)

#define	LLDP_CAPSTR_OTHER	"other"
#define	LLDP_CAPSTR_REPEATER	"repeater"
#define	LLDP_CAPSTR_MAC_BRIDGE	"bridge"
#define	LLDP_CAPSTR_AP		"ap"
#define	LLDP_CAPSTR_ROUTER	"router"
#define	LLDP_CAPSTR_PHONE	"phone"
#define	LLDP_CAPSTR_DOCSIS	"docsis"
#define	LLDP_CAPSTR_STATION	"station"
#define	LLDP_CAPSTR_CVLAN	"c-vlan"
#define	LLDP_CAPSTR_SVLAN	"s-vlan"
#define	LLDP_CAPSTR_TPMR	"tpmr"

/*
 * Management address ifnum subtypes
 */
typedef enum lldp_mgmt_ifnum_e {
	LLDP_MGMT_UNKNOWN = 1,
	LLDP_MGMT_IFINDEX,
	LLDP_MGMT_SYSPORT
} lldp_mgmt_ifnum_t;

#define	LLDP_VLAN_SUP		((uint8_t)1 << 0)
#define	LLDP_VLAN_EN		((uint8_t)1 << 1)

#define	LLDP_AGGR_SUP		((uint8_t)1 << 0)
#define	LLDP_AGGR_EN		((uint8_t)1 << 1)

/* Core TLVs that can be sent */
#define	LLDP_TX_PORTDESC	(1UL << 0)
#define	LLDP_TX_SYSNAME		(1UL << 1)
#define	LLDP_TX_SYSDESC		(1UL << 2)
#define	LLDP_TX_SYSCAP		(1UL << 3)
#define	LLDP_TX_MGMTADDR	(1UL << 4)

/* 802.1 TLVs that can be sent */
#define	LLDP_TX_X1_NATIVE_VLAN	(1UL << 0)
#define	LLDP_TX_X1_VLANS	(1UL << 1)
#define	LLDP_TX_X1_VLAN_NAME	(1UL << 2)
#define	LLDP_TX_X1_MGMT_VLAN	(1UL << 3)

/* 802.3 TLVs that can be sent */
#define	LLDP_TX_X3_PHYCFG	(1UL << 0)
#define	LLDP_TX_X3_POWER	(1UL << 1)
#define	LLDP_TX_X3_AGGR		(1UL << 2)
#define	LLDP_TX_X3_MTU		(1UL << 3)

/*
 * names for nvlist
 * values prefixed with a _ are ignored for comparisons
 */

#define	LLDP_TIME	"_timestamp"		/* uint64 */
#define	LLDP_CHASSIS_ID	"chassis id"		/* nvlist */
#define	LLDP_CHASSIS_SUBTYPE	"subtype"	/* uint8 */
/*				"chassis id"	uint8 array */
#define	LLDP_PORT_ID	"port id"		/* nvlist */
#define	LLDP_PORT_SUBTYPE	"subtype"	/* uint8 */
/*				"port id"	uint8 array */
#define	LLDP_TTL	"ttl"			/* uint16 */
#define	LLDP_PORTDESC	"port description"	/* string */
#define	LLDP_SYSNAME	"system name"		/* string */
#define	LLDP_SYSDESC	"system description"	/* string */
#define	LLDP_SYSCAP	"capabilities"		/* nvlist */
#define	LLDP_CAPSUP		"supported"	/* uint16 */
#define	LLDP_CAPEN		"enabled"	/* uint16 */
#define	LLDP_MGMT_ADDR	"management addr"	/* nvlist */
#define	LLDP_MGMT_MADDR		"addr"		/* uint8 array */
#define	LLDP_MGMT_IFNUM_TYPE	"ifnum type"	/* uint8 */
#define	LLDP_MGMT_IFNUM		"ifnum"		/* uint32 */
#define	LLDP_MGMT_OID		"oid"		/* uint8 array */

/* 802.1 */
#define	LLDP_NATIVE_VLAN "native vlan"		/* uint16 */
#define	LLDP_VLAN	"vlan"			/* nvlist */
#define	LLDP_VLAN_ID		"id"		/* uint16 */
#define	LLDP_VLAN_FLAGS		"flags"		/* uint8 */
#define	LLDP_VLAN_NAME		"name"		/* string */
#define	LLDP_VLAN_NAME_MAX 32
#define	LLDP_PROTOCOLS	"protocols"		/* nvlist array */
#define	LLDP_PROTO_ID		"id"		/* uint8 array */
#define	LLDP_VID_DIGEST	"vid digest"		/* uint32 */
#define	LLDP_MGMT_VLAN	"management vlan"	/* uint16 */
#define	LLDP_AGGR	"aggr"			/* nvlist */
#define	LLDP_AGGR_STATUS	"status"	/* uint8 */
#define	LLDP_AGGR_ID		"id"		/* uint32 */

/* 802.3 */
#define	LLDP_PHY_CONIG	"phy config"		/* nvlist */
#define	LLDP_PHY_STATUS		"status"	/* uint8 */
#define	LLDP_PHY_ADV		"advertised"	/* uint16 */
#define	LLDP_PHY_TYPE		"type"		/* uint16 */
#define	LLDP_POWER	"power"			/* nvlist */
#define	LLDP_POWER_MDI		"mdi"		/* uint8 */
#define	LLDP_POWER_PSE		"pse"		/* uint8 */
#define	LLDP_POWER_CLASS	"class"		/* uint8 */
#define	LLDP_MTU	"mtu"			/* uint16 */

typedef uint64_t lldp_linkid_t;
#define	LLDP_LINK_NOT_FOUND 0

void lldp_init(int);
void lldp_read_config(void);

#if 0
lldp_linkid_t lldp_get_linkid(const char *);
void lldp_set_admin_status(lldp_linkid_t, lldp_admin_status_t);
#endif

struct lldp_link_s;
void lldp_set_admin_status(struct lldp_link_s *, lldp_admin_status_t);
void lldp_quit(void);

const char *lldp_status_str(lldp_admin_status_t);

size_t lldp_cap_str(char *, size_t, uint16_t);
size_t lldp_addr_str(char *, size_t, const uint8_t *, size_t);

const char *lldp_chassis_substr(lldp_chassis_id_t);
size_t lldp_chassis_str(char *, size_t, lldp_chassis_id_t, const uint8_t *,
    size_t);

const char *lldp_port_substr(lldp_port_id_t);
size_t lldp_port_str(char *, size_t, lldp_port_id_t, const uint8_t *, size_t);

const char *lldp_mgmt_addr_substr(lldp_mgmt_ifnum_t);

#ifdef __cplusplus
}
#endif

#endif /* _LLDP_H */
