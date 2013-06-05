/*	$OpenBSD: pf.c,v 1.5 2013/03/04 14:00:31 bluhm Exp $	*/

/*
 * Copyright (c) 2012 Joel Knight <joel@openbsd.org>
 * Copyright (c) 2002 Cedric Berger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>

#include "snmpd.h"

int	 devpf = 0;

size_t 	 buf_esize[PFRB_MAX] = { 0,
	sizeof(struct pfr_table), sizeof(struct pfr_tstats),
	sizeof(struct pfr_addr), sizeof(struct pfr_astats),
	sizeof(struct pfi_kif), sizeof(struct pfioc_trans_e)
};

void
pf_init(void)
{
	if ((devpf = open("/dev/pf", O_RDONLY)) == -1)
		fatal("pf_init");
}

int
pf_get_stats(struct pf_status *s)
{
	extern int	 devpf;

	memset(s, 0, sizeof(*s));
	if (ioctl(devpf, DIOCGETSTATUS, s)) {
		log_warn("DIOCGETSTATUS");
		return (-1);
	}

	return (0);
}

int
pfr_get_astats(struct pfr_table *tbl, struct pfr_astats *addr, int *size,
		int flags)
{
	struct pfioc_table	 io;
	extern int		 devpf;

	if (tbl == NULL || size == NULL || *size < 0 ||
	    (*size && addr == NULL)) 
		return (-1);

	bzero(&io, sizeof io);
	io.pfrio_flags = flags;
	io.pfrio_table = *tbl;
	io.pfrio_buffer = addr;
	io.pfrio_esize = sizeof(*addr);
	io.pfrio_size = *size;
	if (ioctl(devpf, DIOCRGETASTATS, &io)) 
		return (-1);
	*size = io.pfrio_size;
	return (0);
}

int
pfr_get_tstats(struct pfr_table *filter, struct pfr_tstats *tbl, int *size,
	int flags)
{
	struct pfioc_table	 io;
	extern int		 devpf;

	if (size == NULL || *size < 0 || (*size && tbl == NULL))
		return (-1);
	bzero(&io, sizeof io);
	io.pfrio_flags = flags;
	if (filter != NULL)
		io.pfrio_table = *filter;
	io.pfrio_buffer = tbl;
	io.pfrio_esize = sizeof(*tbl);
	io.pfrio_size = *size;
	if (ioctl(devpf, DIOCRGETTSTATS, &io))
		return (-1);
