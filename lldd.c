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
 * Copyright 2017 Jason King.  All rights reserved.
 */
#include <sys/types.h>
#include <sys/debug.h>
#include <getopt.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <libgen.h>
#include <locale.h>
#include <err.h>
#include <note.h>
#include <libscf.h>
#include <pthread.h>
#include <synch.h>
#include <string.h>
#include <stdarg.h>
#include <port.h>
#include <atomic.h>
#include <stropts.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/systeminfo.h>

#include "lldd.h"
#include "lldp.h"
#include "cdp.h"

#define	DEFAULT_FMRI "svc:/network/link-layer-discovery:default"

typedef enum hwaddr_style_e {
	HWADDR_COLON,
	HWADDR_DASH,
	HWADDR_CISCO
} hwaddr_style_t;

typedef struct proto_s {
	char *name;
	buf_t id;
} proto_t;

char *hostname = NULL;
char *host_description = NULL;
char *os_name = NULL;
char *os_release = NULL;
char *os_version = NULL;
const char *fmri = NULL;

char *progname;
int dlevel = 0;
FILE *debugf = stdout;
pid_t pid;
boolean_t json = B_FALSE;

list_t links;
uint_t num_links = 0;
size_t link_max_len = 0;

static int main_port;
static hwaddr_style_t hwaddr_style;

static void signal_init(void);
static void *signal_thread(void *);
static void get_port_list(void);
static boolean_t get_sysinfo(void);

static void main_loop(void);

static void
usage(const char *cmd)
{
	(void) fprintf(stderr, gettext("Usage: %s [-nd]\n"), cmd);
#ifdef notyet
	(void) fprintf(stderr, gettext("    -n: Do not fork into "
	    "background.\n"));
#endif
	(void) fprintf(stderr, gettext("    -d: Enable debugging (implies -n)"
	    "\n"));
	exit(EXIT_FAILURE);
}

int
main(int argc, char * const argv[])
{
	int c;
	boolean_t fork = B_TRUE;

	progname = basename(strdup(argv[0]));

	if ((fmri = (const char *)getenv("SMF_FMRI")) == NULL)
		fmri = DEFAULT_FMRI;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "djn")) != EOF) {
		switch (c) {
		case 'd':
			dlevel = 0xffff;
			break;
		case 'j':
			json = B_TRUE;
			break;
		case 'n':
			fork = B_FALSE;
			break;
		default:
			(void) fprintf(stderr, gettext("Unknown option "
			    "\'%c\'.\n"), c);
			usage(progname);
		}
	}

	pid = getpid();

	if ((main_port = port_create()) == -1)
		err(EXIT_FAILURE, "port_create() failed");

	list_create(&links, sizeof (link_t), offsetof(link_t, node));

	VERIFY(get_sysinfo());
	lldp_read_config();
	signal_init();
	get_port_list();
	lldp_init(4);
	cdp_init(4);
	main_loop();

	return (0);
}

static void
set_status(void)
{
	link_t *link;
	lldp_admin_status_t lldp_status = LLDP_LINK_TXRX;

	for (link = (link_t *)list_head(&links);
	    link != NULL;
	    link = (link_t *)list_next(&links, (void *)link))
		lldp_set_admin_status(link->lldp, lldp_status);
}

static void
main_loop(void)
{
	port_event_t pe;
	boolean_t stop = B_FALSE;

	DMSG(D_THREAD, "%s: enter", __func__);

	set_status();

	while (!stop) {
		if (port_get(main_port, &pe, NULL) != 0) {
			DMSG(D_OP, "port_get() failed: %s", strerror(errno));
			continue;
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_USER:
			switch (pe.portev_events) {
			case MM_STOP:
				stop = B_TRUE;
				continue;
			case MM_ADDWORKER:
				break;
			case MM_DELWORKER:
				break;
			case MM_ADDPORT:
				break;
			case MM_DELPORT:
				break;
			default:
				VERIFY(0);
			}
			break;
		default:
			VERIFY(0);
		}
	}

	/* XXX: signal workers to stop */
}

void
notify_main_thread(main_msg_t msg, void *data)
{
	if (port_send(main_port, msg, data) != 0)
		DMSG(D_OP, "port_send(main_port): failed: %s",
		    strerror(errno));
}

void
read_scf_proto_cfg(const char *proto, scf_cfg_t *cfg)
{
	scf_handle_t *handle = NULL;
	scf_scope_t *sc = NULL;
	scf_service_t *svc = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *value_iter = NULL;
	uint64_t val;
	char *str;
	size_t slen;
	int i;

	handle = scf_handle_create(SCF_VERSION);
	sc = scf_scope_create(handle);
	svc = scf_service_create(handle);
	pg = scf_pg_create(handle);
	prop = scf_property_create(handle);
	value = scf_value_create(handle);
	value_iter = scf_iter_create(handle);

	if (handle == NULL || sc == NULL || svc == NULL || pg == NULL ||
	    prop == NULL || value == NULL || value_iter == NULL) {
		DMSG(D_OP, "%s: unable to create smf(5) handles.", proto);
		goto done;
	}

	if (scf_handle_bind(handle) != 0) {
		DMSG(D_OP, "%s: unable to bind smf(5) handle: %s", proto,
		    scf_strerror(scf_error()));
		goto done;
	}

	if (scf_handle_decode_fmri(handle, fmri, sc, svc, NULL, NULL, NULL,
	    0) != 0) {
		DMSG(D_OP, "%s: unable to decode fmri '%s': %s", proto, fmri,
		    scf_strerror(scf_error()));
		goto done;
	}

	if (scf_service_get_pg(svc, proto, pg) != 0 &&
	    scf_error() != SCF_ERROR_NOT_FOUND) {
		DMSG(D_OP, "%s: unable to read '%s' property group: %s",
		    proto, proto, scf_strerror(scf_error()));
		goto done;
	}

	for (i = 0; cfg[i].name != NULL; i++) {
		scf_cfg_t *c = &cfg[i];

		if (scf_pg_get_property(pg, c->name, prop) != 0) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				DMSG(D_OP, "%s: unable to read %s/%s from "
				    "smf: %s", proto, proto, c->name,
				    scf_strerror(scf_error()));

			continue;
		}

		if (scf_property_is_type(prop, c->type) != 0) {
			scf_type_t type;

			if (scf_error() != SCF_ERROR_TYPE_MISMATCH) {
				DMSG(D_OP, "%s: unable to validate "
				    "type of '%s/%s' smf property: %s",
				    proto, proto, c->name,
				    scf_strerror(scf_error()));
				continue;
			}

			if (scf_property_type(prop, &type) != 0) {
				DMSG(D_OP, "%s: unable to obtain "
				    "type of '%s/%s' smf property: %s",
				    proto, proto, c->name,
				    scf_strerror(scf_error()));
				continue;
			}

			DMSG(D_OP, "%s: property '%s/%s' has an unexpected "
			    "type:\n"
			    "   expected type: %s\n"
			    "     actual type: %s\n",
			    proto, proto, c->name,
			    scf_type_to_string(c->type),
			    scf_type_to_string(type));
			continue;
		}

		if (scf_property_get_value(prop, value) != 0) {
			if (scf_error() != SCF_ERROR_NOT_SET)
				DMSG(D_OP, "%s: unable to get value of "
				    "'%s/%s' smf property: %s", proto,
				    proto, c->name, scf_strerror(scf_error()));

			continue;
		}

		switch (c->type) {
		case SCF_TYPE_COUNT:
			if (scf_value_get_count(value, &val) != 0) {
				DMSG(D_OP, "%s: unable to read value of "
				    "'%s/%s' smf property: %s", proto, proto,
				    c->name, scf_strerror(scf_error()));
				continue;
			}

			if (val > c->max) {
				DMSG(D_OP, "%s: value of '%s/%s' smf property "
				    "(%'llu) is out of range (0 - %'zu).",
				    proto, proto, c->name, val, c->max);
				continue;
			}
			*((uint32_t *)c->val) = (uint32_t)val;
			break;
		case SCF_TYPE_ASTRING:
		{
			char **valp = (char **)c->val;
			ssize_t len;

			slen = c->max + 1;
			if ((str = malloc(slen)) == NULL) {
				/* XXX message */
				continue;
			}
			if ((len = scf_value_get_astring(value, str,
			    slen)) >= slen)
				DMSG(D_OP, "%s: length of '%s/%s' "
				    "(%'zd bytes) exceeds maximum "
				    "allowable length (%zu bytes).  The string"
				    " will be truncated.", proto, proto,
				    c->name, len, c->max);

			free(*valp);
			*valp = str;
			break;
		}
		default:
			VERIFY(0);
		}
	}

done:
	scf_iter_destroy(value_iter);
	scf_value_destroy(value);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_service_destroy(svc);
	scf_scope_destroy(sc);
	scf_handle_destroy(handle);
}

static boolean_t
dlpi_walk_cb(const char *name, void *arg)
{
	NOTE(ARGUNUSED(arg))

	dlpi_handle_t dlh;
	link_t *link;
	int rc;
	dlpi_info_t info;
	boolean_t keep;
	size_t len;

	rc = dlpi_open(name, &dlh, DLPI_PASSIVE|DLPI_NATIVE);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET, "dlpi_open(%s) failed: %s; skipping.",
		    name, dlpi_strerror(rc));
		return (B_FALSE);
	}

	rc = dlpi_info(dlh, &info, 0);
	if (rc != DLPI_SUCCESS) {
		DMSG(D_NET, "dlpi_info(%s) failed: %s; skipping.",
		    name, dlpi_strerror(rc));
		dlpi_close(dlh);
		return (B_FALSE);
	}

	keep = !!(info.di_mactype == DL_ETHER);
	DMSG(D_NET, "found link %s, mactype = %s (%d)%s.", name,
	    dlpi_mactype(info.di_mactype), info.di_mactype,
	    (keep) ? "" : "; discarding");

	dlpi_close(dlh);

	if (!keep)
		return (B_FALSE);

	VERIFY((link = link_alloc(name)) != NULL);
	list_insert_tail(&links, (void *)link);
	num_links++;
	if ((len = strlen(name)) > link_max_len)
		link_max_len = len;

	return (B_FALSE);
}

static void
get_port_list(void)
{
	dlpi_walk(dlpi_walk_cb, NULL, 0);
}

link_t *
link_alloc(const char *name)
{
	link_t *link;

	if ((link = calloc(1, sizeof (link_t))) == NULL)
		return (NULL);

	if ((link->name = strdup(name)) == NULL) {
		free(link);
		return (NULL);
	}

	VERIFY(pthread_mutex_init(&link->lock, NULL) == 0);
	return (link);
}

void
link_free(link_t *link)
{
	if (link == NULL)
		return;

	free(link->name);
	VERIFY(pthread_mutex_destroy(&link->lock) == 0);
	free(link);
}

static void
signal_init(void)
{
	pthread_attr_t attr;
	pthread_t tid;
	sigset_t nset;
	int rc;

	(void) sigfillset(&nset);
	(void) pthread_sigmask(SIG_SETMASK, &nset, NULL);

	DMSG(D_THREAD, "Removed signal handling from main thread.");

	if (pthread_attr_init(&attr) != 0)
		err(EXIT_FAILURE, "pthread_attr_init");

	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if ((rc = pthread_create(&tid, &attr, signal_thread, NULL)) != 0)
		errx(EXIT_FAILURE,
		    "pthread_create(signal_handler) failed: %s",
		    strerror(rc));

	DMSG(D_THREAD, "Signal handling thread created.");
}

static void *
signal_thread(void *ignoreme)
{
	NOTE(ARGUNUSED(ignoreme))

	sigset_t sigset;
	int signum;
	boolean_t stop = B_FALSE;

	DMSG(D_THREAD, "signal thread awaiting signals.");

	(void) sigfillset(&sigset);

	while (!stop) {
		const char *sigstr;

		if (sigwait(&sigset, &signum) != 0) {
			DMSG(D_THREAD, "sigwait failed: %s", strerror(errno));
			continue;
		}

		sigstr = (signum < _sys_siglistn) ? _sys_siglist[signum] :
		    _sys_siglist[0];
		DMSG(D_THREAD, "signal %d (%s) caught.", signum, sigstr);

		switch (signum) {
		case SIGHUP:
			break;
		case SIGTERM:
		case SIGINT:
			lldp_quit();
			stop = B_TRUE;
			continue;
		case SIGWAITING:
			break;
		default:
			DMSG(D_THREAD, "ignoring signal %d.", signum);
		}

	}

	DMSG(D_THREAD, "exiting");
	exit(0);

	NOTE(NOTREACHED)
	return (NULL);
}

const char *
lookup_proto(buf_t *proto)
{
	return (NULL);
}

const char *
lookup_vlan(uint16_t id)
{
	return (NULL);
}

static void
notify_handler(dlpi_handle_t dlh, dlpi_notifyinfo_t *ni, void *arg)
{
	link_t *link = (link_t *)arg;
}

void
dprintf(const char *msg, ...)
{
	char timestr[32];
	time_t now = time(NULL);
	va_list ap;

	(void) memset(timestr, 0, sizeof (timestr));
	(void) strftime(timestr, sizeof (timestr) - 1, "%F %T",
	    localtime(&now));

	va_start(ap, msg);

	flockfile(debugf);
	(void) fprintf(debugf, "%s %s/%d: ", timestr, progname, pthread_self());
	(void) vfprintf(debugf, msg, ap);
	(void) fputc('\n', debugf);
	funlockfile(debugf);
	fflush(debugf);
}

static const char hdigits[] = "0123456789abcdef";

/*
 * Format a hardware address as a string.  Returns the length (excluding
 * the NULL) of the string.  If the output buffer is too small, the
 * output will be truncated, but the return will still show what the
 * necessary size would be, e.g.
 *     if (fmt_macaddr(buf, len, addr, addrlen) + 1 > len)
 *        -- buffer is too small
 */
size_t
fmt_macaddr(char *buf, size_t buflen, const uint8_t *addr, size_t addrlen)
{
	char *end = buf + buflen - 1; /* reserve room for NULL */
	int i, inc;
	size_t len = 0;
	char sep;

	if (buflen == 0)
		return (0);

	(void) memset(buf, 0, buflen);

	switch (hwaddr_style) {
	case HWADDR_COLON:
		sep = ':';
		inc = 1;
		break;
	case HWADDR_DASH:
		sep = '-';
		inc = 1;
		break;
	case HWADDR_CISCO:
		sep = '.';
		inc = 2;
		break;
	default:
		VERIFY(0);
	}
	if (inc > addrlen)
		inc = addrlen;

	(void) memset(buf, 0, buflen);
	for (i = 0; i < addrlen; i++) {
		uint8_t val = addr[i];

		if ((i != 0) && (i % inc == 0)) {
			if (buf < end)
				*buf++ = sep;
			len++;
		}

		if (buf + 2 >= end)
			break;

		if (buf + 2 <= end) {
			*buf++ = hdigits[(val >> 4) & 0x0f];
			*buf++ = hdigits[(val & 0x0f)];
		}
		len += 2;
	}

	return (len);
}

/* djb2 hash alg */
uint32_t
link_hash(const char *name)
{
	uint32_t hash = 5381;
	int c;

	while ((c = *name++) != '\0')
		hash = hash * 33 ^ c;
	return (hash);
}

static struct intconv_s {
	uint_t amt;
	char sfx;
} intconv[] = {
	{ 7L * 24L * 60L * 60L, 'w' },
	{ 24L * 60L * 60L, 'd' },
	{ 60L * 60L, 'h' },
	{ 60L, 'm' },
	{ 1L, 's' }
};

ssize_t
interval_str(char *str, size_t len, uint_t iv)
{
	char *p;
	ssize_t out;
	int i, n;
	uint_t amt;
	boolean_t started;

	(void) memset(str, 0, len);

	p = str;
	started = B_FALSE;
	out = 0;
	for (i = 0; i < sizeof (intconv) / sizeof (struct intconv_s); i++) {
		amt = iv / intconv[i].amt;
		iv %= intconv[i].amt;

		if (amt == 0 && !started)
			continue;

		n = snprintf(p, len, "%u%c", amt, intconv[i].sfx);
		p += n;
		out += n;
		len -= n;
		started = B_TRUE;
	}
	return (n);
}

static boolean_t
xsysinfo(int command, char **result)
{
	char *buf;
	int buflen, rc;
	
	*result = NULL;
	if ((buf = calloc(1, 257)) == NULL)
		return (B_FALSE);

	buflen = 257;
	while ((rc = sysinfo(command, buf, buflen)) > 0 && rc < buflen) {
		char *temp = realloc(buf, rc);

		if (temp == NULL) {
			free(buf);
			return (B_FALSE);
		}
		buf = temp;
		buflen = rc;
	}
	*result = buf;

	return ((rc == -1) ? B_FALSE : B_TRUE);
}

static struct sysinfo_s {
	int cmd;
	char **var;
} sysinfo_list[] = {
	{ SI_SYSNAME, &os_name },
	{ SI_HOSTNAME, &hostname },
	{ SI_RELEASE, &os_release },
	{ SI_VERSION, &os_version }
};

static boolean_t
get_sysinfo(void)
{
	int i;

	for (i = 0;
	    i < sizeof (sysinfo_list) / sizeof (struct sysinfo_s);
	    i++) {
		free(*sysinfo_list[i].var);
		if (!xsysinfo(sysinfo_list[i].cmd, sysinfo_list[i].var))
			return (B_FALSE);
	}

	free(host_description);
	i = asprintf(&host_description, "%s %s %s", os_name, os_release,
	    os_version);

	return ((i == -1) ? B_FALSE : B_TRUE);
}

void
buf_dup(buf_t *src, buf_t *dest)
{
	dest->data = src->data;
	dest->len = src->len;
}

uint8_t
get8(buf_t *buf)
{
	uint8_t val;

	ASSERT(buf->len >= sizeof (uint8_t));
	val = *buf->data++;
	buf->len--;
	return (val);
}

uint16_t
get16(buf_t *buf)
{
	uint16_t val = 0;

	ASSERT(buf->len >= sizeof (uint16_t));
	val |= (uint16_t)(*buf->data++) << 8;
	val |= (uint16_t)(*buf->data++);
	buf->len -= sizeof (uint16_t);
	return (val);
}

uint32_t
get32(buf_t *buf)
{
	uint32_t val = 0;

	ASSERT(buf->len >= sizeof (uint32_t));
	val |= (uint32_t)(*buf->data++) << 24;
	val |= (uint32_t)(*buf->data++) << 16;
	val |= (uint32_t)(*buf->data++) << 8;
	val |= (uint32_t)(*buf->data++);
	buf->len -= sizeof (uint32_t);
	return (val);
}

uint64_t
get64(buf_t *buf)
{
	uint64_t val = 0;

	ASSERT(buf->len >= sizeof (uint64_t));
	val |= (uint64_t)(*buf->data++) << 56;
	val |= (uint64_t)(*buf->data++) << 48;
	val |= (uint64_t)(*buf->data++) << 40;
	val |= (uint64_t)(*buf->data++) << 32;
	val |= (uint64_t)(*buf->data++) << 24;
	val |= (uint64_t)(*buf->data++) << 16;
	val |= (uint64_t)(*buf->data++) << 8;
	val |= (uint64_t)(*buf->data++);
	buf->len -= sizeof (uint64_t);
	return (val);
}

void
getmem(buf_t *buf, void *dest, size_t len)
{
	ASSERT(buf->len >= len);

	(void) memcpy(dest, buf->data, len);
	buf->data += len;
	buf->len -= len;
}

boolean_t
put8(buf_t *buf, uint8_t val)
{
	if (buf->len == 0)
		return (B_FALSE);
	*buf->data++ = val;
	buf->len--;
	return (B_TRUE);
}

boolean_t
put16(buf_t *buf, uint16_t val)
{
	if (buf->len < sizeof (uint16_t))
		return (B_FALSE);
	*buf->data++ = (uint8_t)(val >> 8);
	*buf->data++ = (uint8_t)(val & 0xff);
	buf->len -= sizeof (uint16_t);
	return (B_TRUE);
}

boolean_t
put32(buf_t *buf, uint32_t val)
{
	if (buf->len < sizeof (uint32_t))
		return (B_FALSE);
	*buf->data++ = (uint8_t)(val >> 24);
	*buf->data++ = (uint8_t)((val >> 16) & 0xff);
	*buf->data++ = (uint8_t)((val >> 8) & 0xff);
	*buf->data++ = (uint8_t)(val & 0xff);
	buf->len -= sizeof (uint32_t);
	return (B_TRUE);
}

boolean_t
put64(buf_t *buf, uint64_t val)
{
	if (buf->len < sizeof (uint64_t))
		return (B_FALSE);
	*buf->data++ = (uint8_t)(val >> 56);
	*buf->data++ = (uint8_t)(val >> 48);
	*buf->data++ = (uint8_t)(val >> 32);
	*buf->data++ = (uint8_t)(val >> 24);
	*buf->data++ = (uint8_t)(val >> 16);
	*buf->data++ = (uint8_t)(val >> 8);
	*buf->data++ = (uint8_t)(val & 0x0f);
	buf->len -= sizeof (uint64_t);
	return (B_TRUE);
}

boolean_t
putmem(buf_t *buf, const void *addr, size_t len)
{
	if (buf->len < len)
		return (B_FALSE);
	(void) memcpy(buf->data, addr, len);
	buf->data += len;
	buf->len -= len;
	return (B_TRUE);
}

const char *
iana_afstr(iana_af_t type)
{
	switch (type) {
	case IANA_RESERVED:
		return ("RESERVED");
	case IANA_IPV4:
		return ("IPV4");
	case IANA_IPV6:
		return ("IPV6");
	case IANA_NSAP:
		return ("NSAP");
	case IANA_HDLC:
		return ("HDLC");
	case IANA_BBN:
		return ("BBN");
	case IANA_802:
		return ("802");
	case IANA_E163:
		return ("E163");
	case IANA_E164:
		return ("E164");
	case IANA_F69:
		return ("F69");
	case IANA_X121:
		return ("X121");
	case IANA_IPX:
		return ("IPX");
	case IANA_APPLETALK:
		return ("APPLETALK");
	case IANA_DECNET:
		return ("DECNET");
	case IANA_VINES:
		return ("VINES");
	case IANA_E164_NSAP:
		return ("E164_NSAP");
	case IANA_DNS:
		return ("DNS");
	case IANA_DN:
		return ("DN");
	case IANA_AS:
		return ("AS");
	case IANA_XTP4:
		return ("XTP4");
	case IANA_XTP6:
		return ("XTP6");
	case IANA_XTP:
		return ("XTP");
	case IANA_WWPN:
		return ("WWPN");
	case IANA_WWNN:
		return ("WWNN");
	case IANA_GWID:
		return ("GWID");
	case IANA_AFI:
		return ("AFI");
	default:
		return ("Unknown");
	}
}
