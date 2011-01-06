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
	struct passwd	*pw;
	struct event	 ev_sigint;
	struct event	 ev_sigterm;
#ifdef DEBUG
	struct oid	*oid;
#endif

	switch (pid = fork()) {
	case -1:
		fatal("snmpe: cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	env = x_env;

	if (control_init(&env->sc_csock) == -1)
		fatalx("snmpe: control socket setup failed");
	if (control_init(&env->sc_rcsock) == -1)
		fatalx("snmpe: restricted control socket setup failed");

	if ((env->sc_sock = snmpe_bind(&env->sc_address)) == -1)
		fatalx("snmpe: failed to bind SNMP UDP socket");

	if ((pw = getpwnam(SNMPD_USER)) == NULL)
		fatal("snmpe: getpwnam");

#ifndef DEBUG
	if (chroot(pw->pw_dir) == -1)
		fatal("snmpe: chroot");
	if (chdir("/") == -1)
		fatal("snmpe: chdir(\"/\")");
#else
#warning disabling privilege revocation and chroot in DEBUG mode
#endif

	setproctitle("snmp engine");
	snmpd_process = PROC_SNMPE;

#ifndef DEBUG
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("snmpe: cannot drop privileges");
#endif

#ifdef DEBUG
	for (oid = NULL; (oid = smi_foreach(oid, 0)) != NULL;) {
		char	 buf[BUFSIZ];
		smi_oidstring(&oid->o_id, buf, sizeof(buf));
		log_debug("oid %s", buf);
	}
#endif

	event_init();

	signal_set(&ev_sigint, SIGINT, snmpe_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, snmpe_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	close(pipe_parent2snmpe[0]);

	if ((iev_parent = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal("snmpe");

