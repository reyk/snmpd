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
