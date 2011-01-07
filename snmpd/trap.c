/*	$OpenBSD: trap.c,v 1.17 2012/09/17 16:43:59 reyk Exp $	*/

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

#include "snmpd.h"
#include "mib.h"

extern struct snmpd	*env;

void
trap_init(void)
{
	struct ber_oid	 trapoid = OID(MIB_coldStart);

	/*
	 * Send a coldStart to notify that the daemon has been
	 * started and re-initialized.
	 */
	trap_send(&trapoid, NULL);
}

int
trap_imsg(struct imsgev *iev, pid_t pid)
{
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	int			 ret = -1, n, x = 0, state = 0;
	int			 done = 0;
	struct snmp_imsg	*sm;
	u_int32_t		 d;
	u_int64_t		 l;
	u_int8_t		*c;
	char			 ostr[SNMP_MAX_OID_LEN];
	struct ber_element	*ber = NULL, *varbind = NULL, *a;
	size_t			 len = 0;
	struct			 ber_oid o;

	ibuf = &iev->ibuf;
	while (!done) {
		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				goto done;
			if (n == 0)
				break;

			switch (imsg.hdr.type) {
			case IMSG_SNMP_ELEMENT:
				if (imsg.hdr.len < (IMSG_HEADER_SIZE +
				    sizeof(struct snmp_imsg)))
					goto imsgdone;

				sm = (struct snmp_imsg *)imsg.data;

				if (!state++) {
					/* First element must be the trap OID */
					if (sm->snmp_type != SNMP_NULL)
						goto imsgdone;
					ber_string2oid(sm->snmp_oid, &o);
					break;
				}

				ber = ber_add_sequence(ber);
				if (varbind == NULL)
					varbind = ber;
				a = ber_add_oidstring(ber, sm->snmp_oid);

				switch (sm->snmp_type) {
				case SNMP_OBJECT:
					if (sm->snmp_len != sizeof(ostr))
						goto imsgdone;
					bcopy(sm + 1, &ostr, sm->snmp_len);
					a = ber_add_oidstring(a, ostr);
					break;
				case SNMP_BITSTRING:
				case SNMP_OCTETSTRING:
				case SNMP_IPADDR:
					if ((sm->snmp_len < 1) ||
					    (sm->snmp_len >= SNMPD_MAXSTRLEN))
						goto imsgdone;
					c = (u_int8_t *)(sm + 1);
					if (sm->snmp_type == SNMP_BITSTRING)
						a = ber_add_bitstring(a, c,
						    sm->snmp_len);
					else
						a = ber_add_nstring(a, c,
						    sm->snmp_len);
					break;
				case SNMP_NULL:
					a = ber_add_null(a);
					break;
				case SNMP_INTEGER32:
				case SNMP_COUNTER32:
				case SNMP_GAUGE32:
				case SNMP_TIMETICKS:
				case SNMP_OPAQUE:
				case SNMP_UINTEGER32:
					if (sm->snmp_len != sizeof(d))
						goto imsgdone;
					bcopy(sm + 1, &d, sm->snmp_len);
					a = ber_add_integer(a, d);
					break;
				case SNMP_COUNTER64:
					if (sm->snmp_len != sizeof(l))
						goto imsgdone;
					bcopy(sm + 1, &l, sm->snmp_len);
					a = ber_add_integer(a, l);
					break;
				default:
					log_debug("trap_imsg: illegal type %d",
					    sm->snmp_type);
					imsg_free(&imsg);
					goto imsgdone;
				}
				switch (sm->snmp_type) {
