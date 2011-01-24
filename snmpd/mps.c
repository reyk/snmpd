/*	$OpenBSD: mps.c,v 1.17 2012/10/01 11:36:55 reyk Exp $	*/

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
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <net/if_media.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
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

extern struct snmpd *env;

struct ber_oid *
	 mps_table(struct oid *, struct ber_oid *, struct ber_oid *);

int
mps_getstr(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	char			*s = oid->o_data;

	if (s == NULL)
		return (-1);
	*elm = ber_add_string(*elm, s);
	return (0);
}

int
mps_setstr(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	char			*s, *v;

	if ((oid->o_flags & OID_WR) == 0)
		return (-1);

	if (ber->be_class != BER_CLASS_UNIVERSAL ||
	    ber->be_type != BER_TYPE_OCTETSTRING)
		return (-1);
	if (ber_get_string(ber, &s) == -1)
		return (-1);
	if ((v = (void *)strdup(s)) == NULL)
		return (-1);
	if (oid->o_data != NULL)
		free(oid->o_data);
	oid->o_data = v;
	oid->o_val = strlen(v);

	return (0);
}

int
mps_getint(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	*elm = ber_add_integer(*elm, oid->o_val);
	return (0);
}

int
mps_setint(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	long long	 i;

	if (ber_get_integer(*elm, &i) == -1)
		return (-1);
	oid->o_val = i;

	return (0);
}

int
mps_getts(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	*elm = ber_add_integer(*elm, oid->o_val);
	ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
	return (0);
}

struct ber_element *
mps_getreq(struct ber_element *root, struct ber_oid *o, u_int sm_version)
{
	struct ber_element	*elm = root;
	struct oid		 key, *value;
	unsigned long		 error_type = 0;	/* noSuchObject */

	if (o->bo_n > BER_MAX_OID_LEN)
		return (NULL);
	bzero(&key, sizeof(key));
	bcopy(o, &key.o_id, sizeof(struct ber_oid));
	smi_oidlen(&key.o_id);	/* Strip off any trailing .0. */
	value = smi_find(&key);
	if (value == NULL)
		return (NULL);
	if (OID_NOTSET(value))
		return (NULL);

	if (value->o_get == NULL)
		goto fail;

	if (value->o_oidlen == o->bo_n) {
		/* No instance identifier specified. */
		error_type = 1;	/* noSuchInstance */
		goto fail;
	}

	if ((value->o_flags & OID_TABLE) == 0)
		elm = ber_add_oid(elm, o);
	if (value->o_get(value, o, &elm) != 0)
		return (NULL);

	return (elm);

fail:
	if (sm_version == 0)
		return NULL;

	/* Set SNMPv2 extended error response. */
	elm = ber_add_oid(elm, o);
	elm = ber_add_null(elm);
	ber_set_header(elm, BER_CLASS_CONTEXT, error_type);
	return (elm);
}

int
mps_setreq(struct ber_element *ber, struct ber_oid *o)
{
	struct oid		 key, *value;

	smi_oidlen(o);
	if (o->bo_n > BER_MAX_OID_LEN)
		return (-1);
	bzero(&key, sizeof(key));
	bcopy(o, &key.o_id, sizeof(struct ber_oid));
	value = smi_find(&key);
	if (value == NULL)
		return (-1);
	if ((value->o_flags & OID_WR) == 0 ||
	    value->o_set == NULL)
		return (-1);
	return (value->o_set(value, o, &ber));
}

struct ber_element *
mps_getnextreq(struct ber_element *root, struct ber_oid *o)
{
	struct oid		*next = NULL;
	struct ber_element	*ber = root;
	struct oid		 key, *value;
	int			 ret;
	struct ber_oid		 no;

	if (o->bo_n > BER_MAX_OID_LEN)
		return (NULL);
	bzero(&key, sizeof(key));
	bcopy(o, &key.o_id, sizeof(struct ber_oid));
	smi_oidlen(&key.o_id);	/* Strip off any trailing .0. */
	value = smi_find(&key);
	if (value == NULL)
		return (NULL);
	if (value->o_flags & OID_TABLE) {
		/* Get the next table row for this column */
		if (mps_table(value, o, &no) != NULL) {
			bcopy(&no, o, sizeof(*o));
			ret = value->o_get(value, o, &ber);
		} else
			ret = 1;
		switch (ret) {
		case 0:
			return (ber);
		case -1:
			return (NULL);
		case 1:	/* end-of-rows */
			break;
		}
	} else if (o->bo_n == value->o_oidlen && value->o_get != NULL) {
		/* No instance identifier specified. Append .0. */
		if (o->bo_n + 1 > BER_MAX_OID_LEN)
			return (NULL);
		ber = ber_add_noid(ber, o, o->bo_n + 1);
		if ((ret = value->o_get(value, o, &ber)) != 0)
