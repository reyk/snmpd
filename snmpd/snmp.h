/*	$OpenBSD: snmp.h,v 1.10 2012/09/17 16:43:59 reyk Exp $	*/

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

#ifndef SNMP_HEADER
#define SNMP_HEADER

/*
 * SNMP IMSG interface
 */

#define SNMP_MAX_OID_LEN	128	/* max size of the OID _string_ */
#define SNMP_SOCKET		"/var/run/snmpd.sock"

enum snmp_type {
	SNMP_IPADDR		= 0,
	SNMP_COUNTER32		= 1,
	SNMP_GAUGE32		= 2,
	SNMP_UNSIGNED32		= 2,
	SNMP_TIMETICKS		= 3,
	SNMP_OPAQUE		= 4,
	SNMP_NSAPADDR		= 5,
	SNMP_COUNTER64		= 6,
	SNMP_UINTEGER32		= 7,

