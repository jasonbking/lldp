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
#include "lldd.h"
#include "lldp.h"
#include "lldp_int.h"

/*
 * Timers in LLDP are implemented as linked lists sorted by order of
 * expiration (soonest first) by timer (tx, ageout, etc.).
 *
 * The only exception is the tick timer.  It fires once per second (when
 * needed) and updates tx_tick on every link in it's list.
 */

/* nanosec -> tenths of a sec with rounding */
#define	DSEC(x) (((x) + NANOSEC / 20) / (NANOSEC / 10))

/* nanosec -> milliseconds with rounding */
#define	MSEC(x) (((x) + NANOSEC / MILLISEC) / (NANOSEC / MILLISEC))

#define	TIMER_NAME_MAX 18
static const char *lldp_timer_names[] = {
	"tx", "info aging", "port shutdown", "too many neighbors"
};

/*
 * Return the amount of time (in tenths of a second) before
 * the given timer expires.
 */
int
lldp_timer_val(lldp_link_t *link, lldp_timer_id_t timer)
{
	hrtime_t val = link->timers[timer].when;
	hrtime_t now = gethrtime();

	return ((int)((val - now + NANOSEC/20) / (NANOSEC / 10)));
}

/*
 * Enables reception of tick events for a link.
 * Turns the tick timer off/on as needed based on the presense of any
 * links requiring it.
 */
void
lldp_set_tick(lldp_link_t *link, boolean_t on)
{
	if (!on) {
		if (list_link_active(&link->list_tick))
			list_remove(&lldp_worker->tick, (void *)link);

		if (list_is_empty(&lldp_worker->tick))
			lldp_worker->tick_time = 0;
	} else {
		if (list_is_empty(&lldp_worker->tick))
			lldp_worker->tick_time = gethrtime() + NANOSEC;

		if (!list_link_active(&link->list_tick))
			list_insert_tail(&lldp_worker->tick, (void *)link);
	}
}

/*
 * Set the timer to the given value and update the timer list
 */
void
lldp_set_timer(lldp_link_t *link, lldp_timer_id_t timer, int val)
{
	list_t *list = &lldp_worker->timers[timer];
	hrtime_t *tp = &link->timers[timer].when;
	list_node_t *node = &link->timers[timer].node;
	void *prev;

	if (list_link_active(node))
		list_remove(list, (void *)link);

	if (val == 0) {
		*tp = 0;
		return;
	}

	*tp = gethrtime() + (hrtime_t)val * NANOSEC;

	/*
	 * Reinsert in order by time until expiration.  We start at the
	 * tail of the list since it's more likely our insertion spot will
	 * be there than towards the head.
	 */
	for (prev = list_tail(list);
	    prev != NULL;
	    prev = list_prev(list, prev)) {
		hrtime_t cmp = ((lldp_link_t *)prev)->timers[timer].when;

		if (*tp > cmp)
			break;
	}

	list_insert_after(list, prev, (void *)link);
}

/*
 * If the tick timer is armed, process it.
 *
 * The tick timer works a bit differently, in that instead of merely
 * setting the timer value to 0 when it has expired, it sets the
 * tx_tick field of every link that needs it (i.e.
 * link->tx_credit < lldp_tx_credit_max), so that outbound PDUs can
 * be throttled.
 */
static void
lldp_tick(hrtime_t now)
{
	lldp_link_t *link;

	if (lldp_worker->tick_time == 0 || lldp_worker->tick_time > now)
		return;

	/*
	 * if the tick timer has been turned on, we should have something
	 * to process
	 */
	ASSERT(!list_is_empty(&lldp_worker->tick));

	DMSG(D_TIMER|D_LLDP, "lldp: tick timer has fired");

	DMSG(D_TIMER, "lldp: updating tx_tick on");

	for (link = TICK_FIRST; link != NULL; link = TICK_NEXT(link)) {
		DMSG(D_TIMER, "lldp: %*s", link_max_len + 4,
		    dlpi_linkname(link->dlh));
		link->tx_tick = B_TRUE;
		lldp_set_active(link);
	}

	lldp_worker->tick_time = now + NANOSEC;

	DMSG(D_TIMER, "lldp: tick timer rearmed for 1s");
}

/*
 * Check for expired timers.  If any are found, mark them as expired
 * (set their value to 0), and add the link to the active list.
 */
void
lldp_process_timers(void)
{
	list_t *list;
	hrtime_t now = gethrtime();
	int i;

	lldp_tick(now);

	DMSG(D_TIMER, "lldp: processing expired timers");

	for (i = 0; i < LLDP_TIMER_MAX; i++) {
		lldp_link_t *link, *next;

		DMSG(D_TIMER, "lldp: %*s:", TIMER_NAME_MAX + 4,
		    lldp_timer_names[i]);

		list = &lldp_worker->timers[i];
		link = (lldp_link_t *)list_head(list);

		while (link != NULL) {
			hrtime_t *when = &link->timers[i].when;

			/*
			 * if the list contains links with active timers,
			 * they shouldn't already be expired
			 */
			ASSERT(*when != 0);

			next = (lldp_link_t *)list_next(list, (void *)link);

			/* lists are maintained in order by expiration time */
			if (*when > now)
				break;

			DMSG(D_TIMER, "lldp: %*s %s (%.3fs)",
			    TIMER_NAME_MAX + 4, "", dlpi_linkname(link->dlh),
			    (double)(MSEC(*when - now)) / 1000);

			/* mark timer as expired */
			*when = 0;

			/* this really doesn't fit anywhere else */
			if (i == LLDP_TIMER_AGE)
				link->rx_info_age = B_TRUE;

			list_remove(list, (void *)link);
			lldp_set_active(link);
			link = next;
		}
	}

	lldp_run_active();
}

/*
 * Set ts to the soonest timer that will expire.  If we have any expired
 * timers, they are processed before returning.
 *
 * This is used by each worker's main loop to set an upper bound on the
 * amount of time it will wait for an external event (i.e. the timeout to
 * port_get(3c)).
 *
 * If no timers are armed, we return NULL.
 */

timespec_t *
lldp_get_timeout(timespec_t *ts)
{
	hrtime_t delta, when, now;
	int i;

again:

	DMSG(D_TIMER, "lldp: checking status of timers");

	/* Start with largest possible value and work down */
	when = LLONG_MAX;
	now = gethrtime();

	/* Check if the tick timer is armed */
	if (lldp_worker->tick_time != 0) {
		when = lldp_worker->tick_time;
		delta = when - now;
		DMSG(D_TIMER, "lldp: %*s: %lldms", TIMER_NAME_MAX + 2, "tick",
		    MSEC(delta));
	}

	for (i = 0; i < LLDP_TIMER_MAX; i++) {
		list_t *list = &lldp_worker->timers[i];
		lldp_link_t *head;
		hrtime_t tv;
		int msec;

		list = &lldp_worker->timers[i];
		head = (lldp_link_t *)list_head(list);
		if (head == NULL) {
			DMSG(D_TIMER, "lldp: %*s: empty",
			    TIMER_NAME_MAX + 2, lldp_timer_names[i]);
			continue;
		}

		tv = head->timers[i].when;

		/* should have disabled timers */
		ASSERT(tv != 0);

		delta = tv - now;
		msec = MSEC(delta);
		DMSG(D_TIMER, "lldp: %*s: %s in %.3fs",
		    TIMER_NAME_MAX + 2, lldp_timer_names[i],
		    dlpi_linkname(head->dlh), (double)msec / 1000);

		if (tv < when)
			when = tv;
	}

	if (when == LLONG_MAX) {
		DMSG(D_TIMER, "lldp: no timers currently set, setting timeout "
		    "as inf");
		return (NULL);
	}

	delta = when - now;

	if (delta <= 0) {
		DMSG(D_TIMER, "lldp: expired timers, processing");
		lldp_process_timers();
		goto again;
	}

	ts->tv_sec = delta / NANOSEC;
	ts->tv_nsec = delta % NANOSEC;

	DMSG(D_TIMER, "lldp: timeout = %d.%03lds", ts->tv_sec,
	    ts->tv_nsec / (NANOSEC / MILLISEC));
	return (ts);
}
