/*	$OpenBSD: snmpd.h,v 1.43 2013/03/29 12:53:41 gerhard Exp $	*/

/*
 * Copyright (c) 2007, 2008, 2012 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#ifndef _SNMPD_H
#define _SNMPD_H

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/pfvar.h>
#include <net/route.h>

#include "ber.h"
#include <snmp.h>

#include <imsg.h>

/*
 * common definitions for snmpd
 */

#define CONF_FILE		"/etc/snmpd.conf"
#define SNMPD_SOCKET		"/var/run/snmpd.sock"
#define SNMPD_USER		"_snmpd"
#define SNMPD_PORT		161
#define SNMPD_TRAPPORT		162

#define SNMPD_MAXSTRLEN		484
#define SNMPD_MAXCOMMUNITYLEN	SNMPD_MAXSTRLEN
#define SNMPD_MAXVARBIND	0x7fffffff
#define SNMPD_MAXVARBINDLEN	1210
#define SNMPD_MAXENGINEIDLEN	32
#define SNMPD_MAXUSERNAMELEN	32
#define SNMPD_MAXCONTEXNAMELEN	32

#define SNMP_USM_DIGESTLEN	12
#define SNMP_USM_SALTLEN	8
#define SNMP_USM_KEYLEN		64
#define SNMP_CIPHER_KEYLEN	16

#define SMALL_READ_BUF_SIZE	1024
#define READ_BUF_SIZE		65535
#define	RT_BUF_SIZE		16384
#define	MAX_RTSOCK_BUF		(128 * 1024)

#define SNMP_ENGINEID_OLD	0x00
#define SNMP_ENGINEID_NEW	0x80	/* RFC3411 */

#define SNMP_ENGINEID_FMT_IPv4	1
#define SNMP_ENGINEID_FMT_IPv6	2
#define SNMP_ENGINEID_FMT_MAC	3
#define SNMP_ENGINEID_FMT_TEXT	4
#define SNMP_ENGINEID_FMT_OCT	5
#define SNMP_ENGINEID_FMT_EID	128

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_OK,		/* answer to snmpctl requests */
	IMSG_CTL_FAIL,
	IMSG_CTL_END,
	IMSG_CTL_NOTIFY
};

enum {
	PROC_PARENT,	/* Parent process and application interface */
	PROC_SNMPE	/* SNMP engine */
} snmpd_process;

/* initially control.h */
struct control_sock {
	const char	*cs_name;
	struct event	 cs_ev;
	struct event	 cs_evt;
	int		 cs_fd;
	int		 cs_restricted;
};

enum blockmodes {
	BM_NORMAL,
	BM_NONBLOCK
};

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	void			*data;
	short			 events;
};

struct ctl_conn {
	TAILQ_ENTRY(ctl_conn)	 entry;
	u_int8_t		 flags;
#define CTL_CONN_NOTIFY		 0x01
#define CTL_CONN_LOCKED		 0x02	/* restricted mode */
	struct imsgev		 iev;

};
TAILQ_HEAD(ctl_connlist, ctl_conn);
extern  struct ctl_connlist ctl_conns;

/*
 * kroute
 */

union kaddr {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
	char			pad[32];
};

struct kroute {
	struct in_addr	prefix;
	struct in_addr	nexthop;
	u_long		ticks;
	u_int16_t	flags;
	u_short		if_index;
	u_int8_t	prefixlen;
	u_int8_t	priority;
};

struct kroute6 {
	struct in6_addr	prefix;
	struct in6_addr	nexthop;
	u_long		ticks;
	u_int16_t	flags;
	u_short		if_index;
	u_int8_t	prefixlen;
	u_int8_t	priority;
};

struct kif_addr {
	u_short			 if_index;
	union kaddr		 addr;
	union kaddr		 mask;
	union kaddr		 dstbrd;

	TAILQ_ENTRY(kif_addr)	 entry;
	RB_ENTRY(kif_addr)	 node;
};

struct kif {
	char			 if_name[IF_NAMESIZE];
	char			 if_descr[IFDESCRSIZE];
	u_int8_t		 if_lladdr[ETHER_ADDR_LEN];
	struct if_data		 if_data;
	u_long			 if_ticks;
	int			 if_flags;
	u_short			 if_index;
};

#define F_CONNECTED		0x0001
#define F_STATIC		0x0002
#define F_BLACKHOLE		0x0004
#define F_REJECT		0x0008
#define F_DYNAMIC		0x0010

/*
 * Message Processing Subsystem (mps)
 */

struct oid {
	struct ber_oid		 o_id;
#define o_oid			 o_id.bo_id
#define o_oidlen		 o_id.bo_n

	char			*o_name;

	u_int			 o_flags;

	int			 (*o_get)(struct oid *, struct ber_oid *,
				    struct ber_element **);
	int			 (*o_set)(struct oid *, struct ber_oid *,
				    struct ber_element **);
	struct ber_oid		*(*o_table)(struct oid *, struct ber_oid *,
				    struct ber_oid *);

	long long		 o_val;
	void			*o_data;

	RB_ENTRY(oid)		 o_element;
};

#define OID_ROOT		0x00
#define OID_RD			0x01
#define OID_WR			0x02
#define OID_IFSET		0x04	/* only if user-specified value */
#define OID_DYNAMIC		0x08	/* free allocated data */
#define OID_TABLE		0x10	/* dynamic sub-elements */
#define OID_MIB			0x20	/* root-OID of a supported MIB */
#define OID_KEY			0x40	/* lookup tables */

#define OID_RS			(OID_RD|OID_IFSET)
#define OID_WS			(OID_WR|OID_IFSET)
#define OID_RW			(OID_RD|OID_WR)
#define OID_RWS			(OID_RW|OID_IFSET)

#define OID_TRD			(OID_RD|OID_TABLE)
#define OID_TWR			(OID_WR|OID_TABLE)
#define OID_TRS			(OID_RD|OID_IFSET|OID_TABLE)
#define OID_TWS			(OID_WR|OID_IFSET|OID_TABLE)
#define OID_TRW			(OID_RD|OID_WR|OID_TABLE)
#define OID_TRWS		(OID_RW|OID_IFSET|OID_TABLE)

#define OID_NOTSET(_oid)						\
	(((_oid)->o_flags & OID_IFSET) &&				\
	((_oid)->o_data == NULL) && ((_oid)->o_val == 0))

#define OID(...)		{ { __VA_ARGS__ } }
#define MIBDECL(...)		{ { MIB_##__VA_ARGS__ } }, #__VA_ARGS__
#define MIB(...)		{ { MIB_##__VA_ARGS__ } }, NULL
#define MIBEND			{ { 0 } }, NULL

/*
