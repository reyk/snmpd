/*	$OpenBSD: timer.c,v 1.2 2012/09/17 16:43:59 reyk Exp $	*/

/*
 * Copyright (c) 2008 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sched.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "snmpd.h"
#include "mib.h"

extern struct snmpd	*env;

void	 timer_cpu(int, short, void *);
int	 percentages(int, int64_t *, int64_t *, int64_t *, int64_t *);

static int64_t	**cp_time;
static int64_t	**cp_old;
static int64_t	**cp_diff;
struct event	  cpu_ev;

void
timer_cpu(int fd, short event, void *arg)
{
	struct event	*ev = (struct event *)arg;
	struct timeval	 tv = { 60, 0 };	/* every 60 seconds */
	int		 mib[3] = { CTL_KERN, KERN_CPTIME2, 0 }, n;
	size_t		 len;
	int64_t		*cptime2;

	len = CPUSTATES * sizeof(int64_t);
	for (n = 0; n < env->sc_ncpu; n++) {
		mib[2] = n;
		cptime2 = env->sc_cpustates + (CPUSTATES * n);
		if (sysctl(mib, 3, cp_time[n], &len, NULL, 0) == -1)
			continue;
		(void)percentages(CPUSTATES, cptime2, cp_time[n],
		    cp_old[n], cp_diff[n]);
#ifdef DEBUG
		log_debug("timer_cpu: cpu%d %d%% idle in %ds", n,
		    (cptime2[CP_IDLE] > 1000 ?
		    1000 : (cptime2[CP_IDLE] / 10)), tv.tv_sec);
#endif
	}

	evtimer_add(ev, &tv);
}

void
timer_init(void)
{
	int	 mib[] = { CTL_HW, HW_NCPU }, i;
	size_t	 len;

	len = sizeof(env->sc_ncpu);
	if (sysctl(mib, 2, &env->sc_ncpu, &len, NULL, 0) == -1)
		fatal("sysctl");

	env->sc_cpustates = calloc(env->sc_ncpu, CPUSTATES * sizeof(int64_t));
	cp_time = calloc(env->sc_ncpu, sizeof(int64_t *));
	cp_old = calloc(env->sc_ncpu, sizeof(int64_t *));
	cp_diff = calloc(env->sc_ncpu, sizeof(int64_t *));
	if (env->sc_cpustates == NULL ||
	    cp_time == NULL || cp_old == NULL || cp_diff == NULL)
		fatal("calloc");
