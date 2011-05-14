/*	$OpenBSD: kroute.c,v 1.23 2012/11/13 22:08:33 florian Exp $	*/

/*
 * Copyright (c) 2007, 2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
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

extern struct snmpd	*env;

struct {
	struct event		 ks_ev;
	u_long			 ks_iflastchange;
	u_long			 ks_nroutes;	/* 4 billions enough? */
	int			 ks_fd;
	int			 ks_ifd;
	u_short			 ks_nkif;
} kr_state;

struct kroute_node {
	RB_ENTRY(kroute_node)	 entry;
	struct kroute		 r;
	struct kroute_node	*next;
};

struct kroute6_node {
	RB_ENTRY(kroute6_node)	 entry;
	struct kroute6		 r;
	struct kroute6_node	*next;
};

struct kif_node {
	RB_ENTRY(kif_node)	 entry;
	TAILQ_HEAD(, kif_addr)	 addrs;
	struct kif		 k;
};

int	kroute_compare(struct kroute_node *, struct kroute_node *);
int	kroute6_compare(struct kroute6_node *, struct kroute6_node *);
int	kif_compare(struct kif_node *, struct kif_node *);

struct kroute_node	*kroute_find(in_addr_t, u_int8_t, u_int8_t);
struct kroute_node	*kroute_matchgw(struct kroute_node *,
			    struct sockaddr_in *);
int			 kroute_insert(struct kroute_node *);
int			 kroute_remove(struct kroute_node *);
void			 kroute_clear(void);

struct kroute6_node	*kroute6_find(const struct in6_addr *, u_int8_t,
			     u_int8_t);
struct kroute6_node	*kroute6_matchgw(struct kroute6_node *,
			    struct sockaddr_in6 *);
int			 kroute6_insert(struct kroute6_node *);
int			 kroute6_remove(struct kroute6_node *);
void			 kroute6_clear(void);

struct kif_node		*kif_find(u_short);
struct kif_node		*kif_insert(u_short);
int			 kif_remove(struct kif_node *);
void			 kif_clear(void);
struct kif		*kif_update(u_short, int, struct if_data *,
			    struct sockaddr_dl *);

int			 ka_compare(struct kif_addr *, struct kif_addr *);
void			 ka_insert(u_short, struct kif_addr *);
struct kif_addr		*ka_find(struct sockaddr *);
int			 ka_remove(struct kif_addr *);

u_int8_t	prefixlen_classful(in_addr_t);
u_int8_t	mask2prefixlen(in_addr_t);
in_addr_t	prefixlen2mask(u_int8_t);
u_int8_t	mask2prefixlen6(struct sockaddr_in6 *);
struct in6_addr *prefixlen2mask6(u_int8_t);
void		get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
void		if_change(u_short, int, struct if_data *, struct sockaddr_dl *);
void		if_newaddr(u_short, struct sockaddr *, struct sockaddr *,
		    struct sockaddr *);
void		if_deladdr(u_short, struct sockaddr *, struct sockaddr *,
		    struct sockaddr *);
void		if_announce(void *);

int		fetchtable(void);
int		fetchifs(u_short);
void		dispatch_rtmsg(int, short, void *);
int		rtmsg_process(char *, int);
int		dispatch_rtmsg_addr(struct rt_msghdr *,
		    struct sockaddr *[RTAX_MAX]);

RB_HEAD(kroute_tree, kroute_node)	krt;
RB_PROTOTYPE(kroute_tree, kroute_node, entry, kroute_compare)
RB_GENERATE(kroute_tree, kroute_node, entry, kroute_compare)

RB_HEAD(kroute6_tree, kroute6_node)	krt6;
RB_PROTOTYPE(kroute6_tree, kroute6_node, entry, kroute6_compare)
RB_GENERATE(kroute6_tree, kroute6_node, entry, kroute6_compare)

RB_HEAD(kif_tree, kif_node)		kit;
RB_PROTOTYPE(kif_tree, kif_node, entry, kif_compare)
RB_GENERATE(kif_tree, kif_node, entry, kif_compare)

RB_HEAD(ka_tree, kif_addr)		kat;
RB_PROTOTYPE(ka_tree, kif_addr, node, ka_compare)
RB_GENERATE(ka_tree, kif_addr, node, ka_compare)

void
kr_init(void)
{
	int		opt = 0, rcvbuf, default_rcvbuf;
	socklen_t	optlen;

	if ((kr_state.ks_ifd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("kr_init: ioctl socket");

	if ((kr_state.ks_fd = socket(AF_ROUTE, SOCK_RAW, 0)) == -1)
		fatal("kr_init: route socket");

	/* not interested in my own messages */
	if (setsockopt(kr_state.ks_fd, SOL_SOCKET, SO_USELOOPBACK,
	    &opt, sizeof(opt)) == -1)
		log_warn("kr_init: setsockopt");	/* not fatal */

	if (env->sc_rtfilter && setsockopt(kr_state.ks_fd, PF_ROUTE,
	    ROUTE_MSGFILTER, &env->sc_rtfilter, sizeof(env->sc_rtfilter)) == -1)
		log_warn("kr_init: setsockopt(ROUTE_MSGFILTER)");

	/* grow receive buffer, don't wanna miss messages */
	optlen = sizeof(default_rcvbuf);
	if (getsockopt(kr_state.ks_fd, SOL_SOCKET, SO_RCVBUF,
	    &default_rcvbuf, &optlen) == -1)
		log_warn("kr_init getsockopt SOL_SOCKET SO_RCVBUF");
	else
		for (rcvbuf = MAX_RTSOCK_BUF;
		    rcvbuf > default_rcvbuf &&
		    setsockopt(kr_state.ks_fd, SOL_SOCKET, SO_RCVBUF,
		    &rcvbuf, sizeof(rcvbuf)) == -1 && errno == ENOBUFS;
		    rcvbuf /= 2)
			;	/* nothing */

	RB_INIT(&krt);
	RB_INIT(&krt6);
	RB_INIT(&kit);
	RB_INIT(&kat);

	if (fetchifs(0) == -1)
		fatalx("kr_init fetchifs");
	if (fetchtable() == -1)
		fatalx("kr_init fetchtable");

	event_set(&kr_state.ks_ev, kr_state.ks_fd, EV_READ | EV_PERSIST,
	    dispatch_rtmsg, NULL);
	event_add(&kr_state.ks_ev, NULL);
}

void
kr_shutdown(void)
{
	kroute_clear();
	kif_clear();
}

u_int
kr_ifnumber(void)
{
	return (kr_state.ks_nkif);
}

u_long
kr_iflastchange(void)
{
	return (kr_state.ks_iflastchange);
}

int
kr_updateif(u_int if_index)
{
	struct kif_node	*kn;

	if ((kn = kif_find(if_index)) != NULL)
		kif_remove(kn);

	/* Do not update the interface address list */
	return (fetchifs(if_index));
}

u_long
kr_routenumber(void)
{
	return (kr_state.ks_nroutes);
}

/* rb-tree compare */
int
kroute_compare(struct kroute_node *a, struct kroute_node *b)
{
	if (ntohl(a->r.prefix.s_addr) < ntohl(b->r.prefix.s_addr))
		return (-1);
	if (ntohl(a->r.prefix.s_addr) > ntohl(b->r.prefix.s_addr))
		return (1);
	if (a->r.prefixlen < b->r.prefixlen)
		return (-1);
	if (a->r.prefixlen > b->r.prefixlen)
		return (1);

	/* if the priority is RTP_ANY finish on the first address hit */
	if (a->r.priority == RTP_ANY || b->r.priority == RTP_ANY)
		return (0);
	if (a->r.priority < b->r.priority)
		return (-1);
	if (a->r.priority > b->r.priority)
		return (1);
	return (0);
}

int
kroute6_compare(struct kroute6_node *a, struct kroute6_node *b)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (a->r.prefix.s6_addr[i] < b->r.prefix.s6_addr[i])
			return (-1);
		if (a->r.prefix.s6_addr[i] > b->r.prefix.s6_addr[i])
			return (1);
	}

	if (a->r.prefixlen < b->r.prefixlen)
		return (-1);
	if (a->r.prefixlen > b->r.prefixlen)
		return (1);

	/* if the priority is RTP_ANY finish on the first address hit */
	if (a->r.priority == RTP_ANY || b->r.priority == RTP_ANY)
		return (0);
	if (a->r.priority < b->r.priority)
		return (-1);
	if (a->r.priority > b->r.priority)
		return (1);
	return (0);
}

int
kif_compare(struct kif_node *a, struct kif_node *b)
{
	return (a->k.if_index - b->k.if_index);
}

int
ka_compare(struct kif_addr *a, struct kif_addr *b)
{
	if (a->addr.sa.sa_family < b->addr.sa.sa_family)
		return (-1);
	if (a->addr.sa.sa_family > b->addr.sa.sa_family)
		return (1);
	return (memcmp(&a->addr.sa, &b->addr.sa, a->addr.sa.sa_len));
}

/* tree management */
struct kroute_node *
kroute_find(in_addr_t prefix, u_int8_t prefixlen, u_int8_t prio)
{
	struct kroute_node	s;
	struct kroute_node	*kn, *tmp;

	s.r.prefix.s_addr = prefix;
	s.r.prefixlen = prefixlen;
	s.r.priority = prio;

	kn = RB_FIND(kroute_tree, &krt, &s);
	if (kn && prio == RTP_ANY) {
		tmp = RB_PREV(kroute_tree, &krt, kn);
		while (tmp) {
			if (kroute_compare(&s, tmp) == 0)
				kn = tmp;
			else
				break;
			tmp = RB_PREV(kroute_tree, &krt, kn);
		}
	}
	return (kn);
}

struct kroute_node *
kroute_matchgw(struct kroute_node *kr, struct sockaddr_in *sa_in)
{
	in_addr_t	nexthop;

	if (sa_in == NULL) {
		log_warnx("kroute_matchgw: no nexthop defined");
		return (NULL);
	}
	nexthop = sa_in->sin_addr.s_addr;

	while (kr) {
		if (kr->r.nexthop.s_addr == nexthop)
			return (kr);
		kr = kr->next;
	}

	return (NULL);
}

int
kroute_insert(struct kroute_node *kr)
{
	struct kroute_node	*krm;

	if ((krm = RB_INSERT(kroute_tree, &krt, kr)) != NULL) {
		/* multipath route, add at end of list */
		while (krm->next != NULL)
			krm = krm->next;
		krm->next = kr;
		kr->next = NULL; /* to be sure */
	}

	kr_state.ks_nroutes++;
	return (0);
}

int
kroute_remove(struct kroute_node *kr)
{
	struct kroute_node	*krm;

	if ((krm = RB_FIND(kroute_tree, &krt, kr)) == NULL) {
		log_warnx("kroute_remove failed to find %s/%u",
		    inet_ntoa(kr->r.prefix), kr->r.prefixlen);
		return (-1);
	}

	if (krm == kr) {
		/* head element */
		if (RB_REMOVE(kroute_tree, &krt, kr) == NULL) {
			log_warnx("kroute_remove failed for %s/%u",
			    inet_ntoa(kr->r.prefix), kr->r.prefixlen);
			return (-1);
		}
		if (kr->next != NULL) {
			if (RB_INSERT(kroute_tree, &krt, kr->next) != NULL) {
				log_warnx("kroute_remove failed to add %s/%u",
				    inet_ntoa(kr->r.prefix), kr->r.prefixlen);
				return (-1);
			}
		}
	} else {
		/* somewhere in the list */
		while (krm->next != kr && krm->next != NULL)
			krm = krm->next;
		if (krm->next == NULL) {
			log_warnx("kroute_remove multipath list corrupted "
			    "for %s/%u", inet_ntoa(kr->r.prefix),
			    kr->r.prefixlen);
			return (-1);
		}
		krm->next = kr->next;
	}

	kr_state.ks_nroutes--;
	free(kr);
	return (0);
}

void
kroute_clear(void)
{
	struct kroute_node	*kr;

	while ((kr = RB_MIN(kroute_tree, &krt)) != NULL)
		kroute_remove(kr);
}

struct kroute6_node *
kroute6_find(const struct in6_addr *prefix, u_int8_t prefixlen, u_int8_t prio)
{
	struct kroute6_node	s;
	struct kroute6_node	*kn6, *tmp;

	memcpy(&s.r.prefix, prefix, sizeof(struct in6_addr));
	s.r.prefixlen = prefixlen;
	s.r.priority = prio;

	kn6 = RB_FIND(kroute6_tree, &krt6, &s);
	if (kn6 && prio == RTP_ANY) {
		tmp = RB_PREV(kroute6_tree, &krt6, kn6);
		while (tmp) {
			if (kroute6_compare(&s, tmp) == 0)
				kn6 = tmp;
			else
				break;
			tmp = RB_PREV(kroute6_tree, &krt6, kn6);
		}
	}
	return (kn6);
}

struct kroute6_node *
kroute6_matchgw(struct kroute6_node *kr, struct sockaddr_in6 *sa_in6)
{
	struct in6_addr	nexthop;

	if (sa_in6 == NULL) {
		log_warnx("kroute6_matchgw: no nexthop defined");
		return (NULL);
	}
	memcpy(&nexthop, &sa_in6->sin6_addr, sizeof(nexthop));

	while (kr) {
		if (memcmp(&kr->r.nexthop, &nexthop, sizeof(nexthop)) == 0)
			return (kr);
		kr = kr->next;
	}

	return (NULL);
}

int
kroute6_insert(struct kroute6_node *kr)
{
	struct kroute6_node	*krm;

	if ((krm = RB_INSERT(kroute6_tree, &krt6, kr)) != NULL) {
		/* multipath route, add at end of list */
		while (krm->next != NULL)
			krm = krm->next;
		krm->next = kr;
		kr->next = NULL; /* to be sure */
	}

	kr_state.ks_nroutes++;
	return (0);
}

int
kroute6_remove(struct kroute6_node *kr)
{
	struct kroute6_node	*krm;

	if ((krm = RB_FIND(kroute6_tree, &krt6, kr)) == NULL) {
		log_warnx("kroute6_remove failed for %s/%u",
		    log_in6addr(&kr->r.prefix), kr->r.prefixlen);
		return (-1);
	}

	if (krm == kr) {
		/* head element */
		if (RB_REMOVE(kroute6_tree, &krt6, kr) == NULL) {
			log_warnx("kroute6_remove failed for %s/%u",
			    log_in6addr(&kr->r.prefix), kr->r.prefixlen);
			return (-1);
		}
		if (kr->next != NULL) {
			if (RB_INSERT(kroute6_tree, &krt6, kr->next) != NULL) {
				log_warnx("kroute6_remove failed to add %s/%u",
				    log_in6addr(&kr->r.prefix),
				    kr->r.prefixlen);
				return (-1);
			}
		}
	} else {
		/* somewhere in the list */
		while (krm->next != kr && krm->next != NULL)
			krm = krm->next;
		if (krm->next == NULL) {
			log_warnx("kroute6_remove multipath list corrupted "
			    "for %s/%u", log_in6addr(&kr->r.prefix),
			    kr->r.prefixlen);
			return (-1);
		}
		krm->next = kr->next;
	}

	kr_state.ks_nroutes--;
	free(kr);
	return (0);
}

void
kroute6_clear(void)
{
	struct kroute6_node	*kr;

	while ((kr = RB_MIN(kroute6_tree, &krt6)) != NULL)
		kroute6_remove(kr);
}

struct kif_node *
kif_find(u_short if_index)
{
	struct kif_node	s;

	if (if_index == 0)
		return (RB_MIN(kif_tree, &kit));

	bzero(&s, sizeof(s));
	s.k.if_index = if_index;

	return (RB_FIND(kif_tree, &kit, &s));
}

struct kif *
kr_getif(u_short if_index)
{
	struct kif_node	*kn;

	kn = kif_find(if_index);
	if (kn == NULL)
		return (NULL);

	return (&kn->k);
}

struct kif *
kr_getnextif(u_short if_index)
{
	struct kif_node	*kn;

	if ((kn = kif_find(if_index)) == NULL)
		return (NULL);
	if (if_index)
		kn = RB_NEXT(kif_tree, &kit, kn);
	if (kn == NULL)
		return (NULL);

	return (&kn->k);
}

struct kif_node *
kif_insert(u_short if_index)
{
	struct kif_node	*kif;

	if ((kif = calloc(1, sizeof(struct kif_node))) == NULL)
		return (NULL);

	kif->k.if_index = if_index;
	TAILQ_INIT(&kif->addrs);

	if (RB_INSERT(kif_tree, &kit, kif) != NULL)
		fatalx("kif_insert: RB_INSERT");

	kr_state.ks_nkif++;
	kr_state.ks_iflastchange = smi_getticks();

	return (kif);
}

int
kif_remove(struct kif_node *kif)
{
	struct kif_addr	*ka;

	if (RB_REMOVE(kif_tree, &kit, kif) == NULL) {
		log_warnx("RB_REMOVE(kif_tree, &kit, kif)");
		return (-1);
	}

	while ((ka = TAILQ_FIRST(&kif->addrs)) != NULL) {
		TAILQ_REMOVE(&kif->addrs, ka, entry);
		ka_remove(ka);
	}
	free(kif);

	kr_state.ks_nkif--;
	kr_state.ks_iflastchange = smi_getticks();

	return (0);
}

void
kif_clear(void)
{
	struct kif_node	*kif;

	while ((kif = RB_MIN(kif_tree, &kit)) != NULL)
		kif_remove(kif);
	kr_state.ks_nkif = 0;
	kr_state.ks_iflastchange = smi_getticks();
}

struct kif *
kif_update(u_short if_index, int flags, struct if_data *ifd,
    struct sockaddr_dl *sdl)
{
	struct kif_node		*kif;
	struct ether_addr	*ea;
	struct ifreq		 ifr;

	if ((kif = kif_find(if_index)) == NULL)
		if ((kif = kif_insert(if_index)) == NULL)
			return (NULL);

	kif->k.if_flags = flags;
	bcopy(ifd, &kif->k.if_data, sizeof(struct if_data));
	kif->k.if_ticks = smi_getticks();

	if (sdl && sdl->sdl_family == AF_LINK) {
		if (sdl->sdl_nlen >= sizeof(kif->k.if_name))
			memcpy(kif->k.if_name, sdl->sdl_data,
			    sizeof(kif->k.if_name) - 1);
		else if (sdl->sdl_nlen > 0)
			memcpy(kif->k.if_name, sdl->sdl_data,
			    sdl->sdl_nlen);
		/* string already terminated via calloc() */

		if ((ea = (struct ether_addr *)LLADDR(sdl)) != NULL)
			bcopy(&ea->ether_addr_octet, kif->k.if_lladdr,
			    ETHER_ADDR_LEN);
	}

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, kif->k.if_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&kif->k.if_descr;
	if (ioctl(kr_state.ks_ifd, SIOCGIFDESCR, &ifr) == -1)
		bzero(&kif->k.if_descr, sizeof(kif->k.if_descr));

	return (&kif->k);
}

void
