/*	$OpenBSD: mib.c,v 1.64 2013/03/11 19:49:37 sthen Exp $	*/

/*
 * Copyright (c) 2012 Joel Knight <joel@openbsd.org>
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
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/sensors.h>
#include <sys/sched.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/disk.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_carp.h>
#include <netinet/ip_var.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <kvm.h>

#include "snmpd.h"
#include "mib.h"

extern struct snmpd	*env;

/*
 * Defined in SNMPv2-MIB.txt (RFC 3418)
 */

int	 mib_getsys(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_getsnmp(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_sysor(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_setsnmp(struct oid *, struct ber_oid *, struct ber_element **);

static struct oid mib_tree[] = MIB_TREE;
static struct ber_oid zerodotzero = { { 0, 0 }, 2 };

#define sizeofa(_a) (sizeof(_a) / sizeof((_a)[0]))

/* base MIB tree */
static struct oid base_mib[] = {
	{ MIB(mib_2),			OID_MIB },
	{ MIB(sysDescr),		OID_RD, mib_getsys },
	{ MIB(sysOID),			OID_RD, mib_getsys },
	{ MIB(sysUpTime),		OID_RD, mib_getsys },
	{ MIB(sysContact),		OID_RW, mib_getsys, mps_setstr },
	{ MIB(sysName),			OID_RW, mib_getsys, mps_setstr },
	{ MIB(sysLocation),		OID_RW, mib_getsys, mps_setstr },
	{ MIB(sysServices),		OID_RS, mib_getsys },
	{ MIB(sysORLastChange),		OID_RD, mps_getts },
	{ MIB(sysORIndex),		OID_TRD, mib_sysor },
	{ MIB(sysORID),			OID_TRD, mib_sysor },
	{ MIB(sysORDescr),		OID_TRD, mib_sysor },
	{ MIB(sysORUpTime),		OID_TRD, mib_sysor },
	{ MIB(snmp),			OID_MIB },
	{ MIB(snmpInPkts),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutPkts),		OID_RD, mib_getsnmp },
	{ MIB(snmpInBadVersions),	OID_RD, mib_getsnmp },
	{ MIB(snmpInBadCommunityNames),	OID_RD, mib_getsnmp },
	{ MIB(snmpInBadCommunityUses),	OID_RD, mib_getsnmp },
	{ MIB(snmpInASNParseErrs),	OID_RD, mib_getsnmp },
	{ MIB(snmpInTooBigs),		OID_RD,	mib_getsnmp },
	{ MIB(snmpInNoSuchNames),	OID_RD, mib_getsnmp },
	{ MIB(snmpInBadValues),		OID_RD, mib_getsnmp },
	{ MIB(snmpInReadOnlys),		OID_RD, mib_getsnmp },
	{ MIB(snmpInGenErrs),		OID_RD, mib_getsnmp },
	{ MIB(snmpInTotalReqVars),	OID_RD, mib_getsnmp },
	{ MIB(snmpInTotalSetVars),	OID_RD, mib_getsnmp },
	{ MIB(snmpInGetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpInGetNexts),		OID_RD, mib_getsnmp },
	{ MIB(snmpInSetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpInGetResponses),	OID_RD, mib_getsnmp },
	{ MIB(snmpInTraps),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutTooBigs),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutNoSuchNames),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutBadValues),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutGenErrs),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutGetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutGetNexts),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutSetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutGetResponses),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutTraps),		OID_RD, mib_getsnmp },
	{ MIB(snmpEnableAuthenTraps),	OID_RW, mib_getsnmp, mib_setsnmp },
	{ MIB(snmpSilentDrops),		OID_RD, mib_getsnmp },
	{ MIB(snmpProxyDrops),		OID_RD, mib_getsnmp },
	{ MIBEND }
};

int
mib_getsys(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_oid		 sysoid = OID(MIB_SYSOID_DEFAULT);
	char			*s = oid->o_data;
	struct ber_oid		*so = oid->o_data;
	struct utsname		 u;
	long long		 ticks;

	if (uname(&u) == -1)
		return (-1);

	switch (oid->o_oid[OIDIDX_system]) {
	case 1:
		if (s == NULL) {
			if (asprintf(&s, "%s %s %s %s %s",
			    u.sysname, u.nodename, u.release,
			    u.version, u.machine) == -1)
				return (-1);
			oid->o_data = s;
			oid->o_val = strlen(s);
		}
		*elm = ber_add_string(*elm, s);
		break;
	case 2:
		if (so == NULL)
			so = &sysoid;
		smi_oidlen(so);
		*elm = ber_add_oid(*elm, so);
		break;
	case 3:
		ticks = smi_getticks();
		*elm = ber_add_integer(*elm, ticks);
		ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
		break;
	case 4:
		if (s == NULL) {
			if (asprintf(&s, "root@%s", u.nodename) == -1)
				return (-1);
			oid->o_data = s;
			oid->o_val = strlen(s);
		}
		*elm = ber_add_string(*elm, s);
		break;
	case 5:
		if (s == NULL) {
			if ((s = strdup(u.nodename)) == NULL)
				return (-1);
			oid->o_data = s;
			oid->o_val = strlen(s);
		}
		*elm = ber_add_string(*elm, s);
		break;
	case 6:
		if (s == NULL)
			s = "";
