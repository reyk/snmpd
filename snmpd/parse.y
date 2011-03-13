/*	$OpenBSD: parse.y,v 1.25 2013/03/29 12:53:41 gerhard Exp $	*/

/*
 * Copyright (c) 2007, 2008, 2012 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <netinet/in.h>
#include <net/if.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <ctype.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>

#include "snmpd.h"
#include "mib.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...);
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

struct snmpd			*conf = NULL;
static int			 errors = 0;
static struct addresslist	*hlist;
static struct usmuser		*user = NULL;

struct address	*host_v4(const char *);
struct address	*host_v6(const char *);
int		 host_dns(const char *, struct addresslist *,
		    int, in_port_t, struct ber_oid *, char *);
int		 host(const char *, struct addresslist *,
		    int, in_port_t, struct ber_oid *, char *);

typedef struct {
	union {
		int64_t		 number;
		char		*string;
		struct host	*host;
		struct timeval	 tv;
		struct ber_oid	*oid;
		struct {
			int		 type;
			void		*data;
			long long	 value;
		}		 data;
		enum usmauth	 auth;
		enum usmpriv	 enc;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	INCLUDE
%token  LISTEN ON
%token	SYSTEM CONTACT DESCR LOCATION NAME OBJECTID SERVICES RTFILTER
%token	READONLY READWRITE OCTETSTRING INTEGER COMMUNITY TRAP RECEIVER
%token	SECLEVEL NONE AUTH ENC USER AUTHKEY ENCKEY ERROR DISABLED
%token	<v.string>	STRING
%token  <v.number>	NUMBER
%type	<v.string>	hostcmn
%type	<v.number>	optwrite yesno seclevel
%type	<v.data>	objtype
%type	<v.oid>		oid hostoid
%type	<v.auth>	auth
%type	<v.enc>		enc

%%

grammar		: /* empty */
		| grammar include '\n'
		| grammar '\n'
		| grammar varset '\n'
		| grammar main '\n'
		| grammar system '\n'
		| grammar mib '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

varset		: STRING '=' STRING	{
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

yesno		:  STRING			{
			if (!strcmp($1, "yes"))
				$$ = 1;
			else if (!strcmp($1, "no"))
				$$ = 0;
			else {
				yyerror("syntax error, "
				    "either yes or no expected");
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

main		: LISTEN ON STRING		{
			struct addresslist	 al;
			struct address		*h;

			TAILQ_INIT(&al);
			if (host($3, &al, 1, SNMPD_PORT, NULL, NULL) <= 0) {
				yyerror("invalid ip address: %s", $3);
				free($3);
				YYERROR;
			}
			free($3);
			h = TAILQ_FIRST(&al);
			bcopy(&h->ss, &conf->sc_address.ss, sizeof(*h));
			conf->sc_address.port = h->port;

			while ((h = TAILQ_FIRST(&al)) != NULL) {
				TAILQ_REMOVE(&al, h, entry);
				free(h);
			}
		}
		| READONLY COMMUNITY STRING	{
			if (strlcpy(conf->sc_rdcommunity, $3,
			    sizeof(conf->sc_rdcommunity)) >=
			    sizeof(conf->sc_rdcommunity)) {
				yyerror("r/o community name too long");
				free($3);
				YYERROR;
			}
			free($3);
		}
		| READWRITE COMMUNITY STRING	{
			if (strlcpy(conf->sc_rwcommunity, $3,
			    sizeof(conf->sc_rwcommunity)) >=
			    sizeof(conf->sc_rwcommunity)) {
				yyerror("r/w community name too long");
				free($3);
				YYERROR;
			}
			free($3);
		}
		| READWRITE DISABLED {
			conf->sc_readonly = 1;
 		}
		| TRAP COMMUNITY STRING		{
			if (strlcpy(conf->sc_trcommunity, $3,
			    sizeof(conf->sc_trcommunity)) >=
			    sizeof(conf->sc_trcommunity)) {
				yyerror("r/w community name too long");
				free($3);
				YYERROR;
			}
			free($3);
		}
		| TRAP RECEIVER			{
			hlist = &conf->sc_trapreceivers;
		} host				{
			hlist = NULL;
		}
		| RTFILTER yesno		{
			if ($2 == 1)
				conf->sc_rtfilter = ROUTE_FILTER(RTM_NEWADDR) |
				    ROUTE_FILTER(RTM_DELADDR) |
				    ROUTE_FILTER(RTM_IFINFO) |
				    ROUTE_FILTER(RTM_IFANNOUNCE);
			else
				conf->sc_rtfilter = 0;
		}
		| SECLEVEL seclevel {
			conf->sc_min_seclevel = $2;
		}
		| USER STRING			{
			const char *errstr;
			user = usm_newuser($2, &errstr);
			if (user == NULL) {
				yyerror(errstr);
				free($2);
				YYERROR;
			}
		} userspecs {
			const char *errstr;
			if (usm_checkuser(user, &errstr) < 0) {
				yyerror(errstr);
				YYERROR;
			}
			user = NULL;
		}
		;

system		: SYSTEM sysmib
		;

sysmib		: CONTACT STRING		{
			struct ber_oid	 o = OID(MIB_sysContact);
			mps_set(&o, $2, strlen($2));
		}
		| DESCR STRING			{
			struct ber_oid	 o = OID(MIB_sysDescr);
			mps_set(&o, $2, strlen($2));
		}
		| LOCATION STRING		{
			struct ber_oid	 o = OID(MIB_sysLocation);
			mps_set(&o, $2, strlen($2));
		}
		| NAME STRING			{
			struct ber_oid	 o = OID(MIB_sysName);
			mps_set(&o, $2, strlen($2));
		}
		| OBJECTID oid			{
			struct ber_oid	 o = OID(MIB_sysOID);
			mps_set(&o, $2, sizeof(struct ber_oid));
		}
		| SERVICES NUMBER		{
			struct ber_oid	 o = OID(MIB_sysServices);
			mps_set(&o, NULL, $2);
		}
		;

mib		: OBJECTID oid NAME STRING optwrite objtype	{
			struct oid	*oid;
			if ((oid = (struct oid *)
			    calloc(1, sizeof(*oid))) == NULL) {
				yyerror("calloc");
				free($2);
				free($6.data);
				YYERROR;
			}

			smi_oidlen($2);
			bcopy($2, &oid->o_id, sizeof(struct ber_oid));
			free($2);
			oid->o_name = $4;
			oid->o_data = $6.data;
			oid->o_val = $6.value;
			switch ($6.type) {
			case 1:
				oid->o_get = mps_getint;
				oid->o_set = mps_setint;
				break;
			case 2:
				oid->o_get = mps_getstr;
				oid->o_set = mps_setstr;
				break;
			}
			oid->o_flags = OID_RD|OID_DYNAMIC;
			if ($5)
				oid->o_flags |= OID_WR;

			smi_insert(oid);
		}
		;

objtype		: INTEGER NUMBER			{
			$$.type = 1;
			$$.data = NULL;
			$$.value = $2;
		}
		| OCTETSTRING STRING			{
			$$.type = 2;
			$$.data = $2;
			$$.value = strlen($2);
		}
		;

optwrite	: READONLY				{ $$ = 0; }
		| READWRITE				{ $$ = 1; }
		;

oid		: STRING				{
			struct ber_oid	*sysoid;
			if ((sysoid =
			    calloc(1, sizeof(*sysoid))) == NULL) {
				yyerror("calloc");
				free($1);
				YYERROR;
			}
			if (ber_string2oid($1, sysoid) == -1) {
				yyerror("invalid OID: %s", $1);
				free(sysoid);
				free($1);
				YYERROR;
			}
			free($1);
			$$ = sysoid;
		}
		;

hostoid		: /* empty */				{ $$ = NULL; }
		| OBJECTID oid				{ $$ = $2; }
		;

hostcmn		: /* empty */				{ $$ = NULL; }
		| COMMUNITY STRING			{ $$ = $2; }
		;

hostdef		: STRING hostoid hostcmn		{
			if (host($1, hlist, 1,
			    SNMPD_TRAPPORT, $2, $3) <= 0) {
				yyerror("invalid host: %s", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

hostlist	: /* empty */
		| hostlist comma hostdef
		;

host		: hostdef
		| '{' hostlist '}'
		;

comma		: /* empty */
		| ','
		;

seclevel	: NONE		{ $$ = 0; }
		| AUTH		{ $$ = SNMP_MSGFLAG_AUTH; }
		| ENC		{ $$ = SNMP_MSGFLAG_AUTH | SNMP_MSGFLAG_PRIV; }
		;

userspecs	: /* empty */
		| userspecs userspec
		;

userspec	: AUTHKEY STRING		{
			user->uu_authkey = $2;
		}
