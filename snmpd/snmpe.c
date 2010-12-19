/*	$OpenBSD: snmpe.c,v 1.33 2013/03/29 12:53:41 gerhard Exp $	*/

/*
 * Copyright (c) 2007, 2008, 2012 Reyk Floeter <reyk@openbsd.org>
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/tree.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <vis.h>

#include "snmpd.h"
#include "mib.h"

int	 snmpe_parse(struct sockaddr_storage *,
	    struct ber_element *, struct snmp_message *);
unsigned long
	 snmpe_application(struct ber_element *);
void	 snmpe_sig_handler(int sig, short, void *);
void	 snmpe_shutdown(void);
void	 snmpe_dispatch_parent(int, short, void *);
int	 snmpe_bind(struct address *);
void	 snmpe_recvmsg(int fd, short, void *);
int	 snmpe_encode(struct snmp_message *);

struct snmpd	*env = NULL;

struct imsgev	*iev_parent;

void
snmpe_sig_handler(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		snmpe_shutdown();
		break;
	default:
		fatalx("snmpe_sig_handler: unexpected signal");
	}
}

pid_t
snmpe(struct snmpd *x_env, int pipe_parent2snmpe[2])
{
	pid_t		 pid;
