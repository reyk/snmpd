/*	$OpenBSD: ber.c,v 1.24 2012/09/17 16:30:34 reyk Exp $ */

/*
 * Copyright (c) 2007, 2012 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006, 2007 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2006, 2007 Marc Balmer <mbalmer@openbsd.org>
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

#include <sys/types.h>
#include <sys/param.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <err.h>	/* XXX for debug output */
#include <stdio.h>	/* XXX for debug output */
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>

#include "ber.h"


#define BER_TYPE_CONSTRUCTED	0x20	/* otherwise primitive */
#define BER_TYPE_SINGLE_MAX	30
#define BER_TAG_MASK		0x1f
#define BER_TAG_MORE		0x80	/* more subsequent octets */
#define BER_TAG_TYPE_MASK	0x7f
#define BER_CLASS_SHIFT		6

static int	ber_dump_element(struct ber *ber, struct ber_element *root);
static void	ber_dump_header(struct ber *ber, struct ber_element *root);
static void	ber_putc(struct ber *ber, u_char c);
static void	ber_write(struct ber *ber, void *buf, size_t len);
static ssize_t	get_id(struct ber *b, unsigned long *tag, int *class,
    int *cstruct);
static ssize_t	get_len(struct ber *b, ssize_t *len);
static ssize_t	ber_read_element(struct ber *ber, struct ber_element *elm);
static ssize_t	ber_readbuf(struct ber *b, void *buf, size_t nbytes);
static ssize_t	ber_getc(struct ber *b, u_char *c);
static ssize_t	ber_read(struct ber *ber, void *buf, size_t len);

#ifdef DEBUG
#define DPRINTF(...)	printf(__VA_ARGS__)
#else
#define DPRINTF(...)	do { } while (0)
#endif

struct ber_element *
ber_get_element(unsigned long encoding)
{
	struct ber_element *elm;

	if ((elm = calloc(1, sizeof(*elm))) == NULL)
		return NULL;

	elm->be_encoding = encoding;
	ber_set_header(elm, BER_CLASS_UNIVERSAL, BER_TYPE_DEFAULT);

	return elm;
}

void
ber_set_header(struct ber_element *elm, int class, unsigned long type)
{
	elm->be_class = class & BER_CLASS_MASK;
	if (type == BER_TYPE_DEFAULT)
		type = elm->be_encoding;
	elm->be_type = type;
}

void
ber_link_elements(struct ber_element *prev, struct ber_element *elm)
{
	if (prev != NULL) {
		if ((prev->be_encoding == BER_TYPE_SEQUENCE ||
		    prev->be_encoding == BER_TYPE_SET) &&
		    prev->be_sub == NULL)
			prev->be_sub = elm;
		else
			prev->be_next = elm;
	}
}

struct ber_element *
ber_unlink_elements(struct ber_element *prev)
{
	struct ber_element *elm;

	if ((prev->be_encoding == BER_TYPE_SEQUENCE ||
	    prev->be_encoding == BER_TYPE_SET) &&
	    prev->be_sub != NULL) {
		elm = prev->be_sub;
		prev->be_sub = NULL;
	} else {
		elm = prev->be_next;
		prev->be_next = NULL;
	}

	return (elm);
}

void
ber_replace_elements(struct ber_element *prev, struct ber_element *new)
{
	struct ber_element *ber, *next;

	ber = ber_unlink_elements(prev);
	next = ber_unlink_elements(ber);
	ber_link_elements(new, next);
	ber_link_elements(prev, new);

	/* cleanup old element */
	ber_free_elements(ber);
}

struct ber_element *
ber_add_sequence(struct ber_element *prev)
{
	struct ber_element *elm;

	if ((elm = ber_get_element(BER_TYPE_SEQUENCE)) == NULL)
		return NULL;

	ber_link_elements(prev, elm);

	return elm;
}

struct ber_element *
ber_add_set(struct ber_element *prev)
{
	struct ber_element *elm;

	if ((elm = ber_get_element(BER_TYPE_SET)) == NULL)
		return NULL;

	ber_link_elements(prev, elm);

	return elm;
}

struct ber_element *
ber_add_enumerated(struct ber_element *prev, long long val)
{
	struct ber_element *elm;
	u_int i, len = 0;
	u_char cur, last = 0;

	if ((elm = ber_get_element(BER_TYPE_ENUMERATED)) == NULL)
		return NULL;

	elm->be_numeric = val;

	for (i = 0; i < sizeof(long long); i++) {
		cur = val & 0xff;
		if (cur != 0 && cur != 0xff)
			len = i;
		if ((cur == 0 && last & 0x80) ||
		    (cur == 0xff && (last & 0x80) == 0))
			len = i;
		val >>= 8;
		last = cur;
	}
	elm->be_len = len + 1;

	ber_link_elements(prev, elm);

	return elm;
}

struct ber_element *
ber_add_integer(struct ber_element *prev, long long val)
{
	struct ber_element *elm;
	u_int i, len = 0;
	u_char cur, last = 0;

	if ((elm = ber_get_element(BER_TYPE_INTEGER)) == NULL)
		return NULL;

	elm->be_numeric = val;

	for (i = 0; i < sizeof(long long); i++) {
		cur = val & 0xff;
		if (cur != 0 && cur != 0xff)
			len = i;
		if ((cur == 0 && last & 0x80) ||
		    (cur == 0xff && (last & 0x80) == 0))
			len = i;
		val >>= 8;
		last = cur;
	}
	elm->be_len = len + 1;

	ber_link_elements(prev, elm);

	return elm;
}

int
ber_get_integer(struct ber_element *elm, long long *n)
{
	if (elm->be_encoding != BER_TYPE_INTEGER)
		return -1;

	*n = elm->be_numeric;
	return 0;
}

int
ber_get_enumerated(struct ber_element *elm, long long *n)
{
	if (elm->be_encoding != BER_TYPE_ENUMERATED)
		return -1;

	*n = elm->be_numeric;
	return 0;
}


struct ber_element *
ber_add_boolean(struct ber_element *prev, int bool)
{
	struct ber_element *elm;

	if ((elm = ber_get_element(BER_TYPE_BOOLEAN)) == NULL)
		return NULL;

	elm->be_numeric = bool ? 0xff : 0;
	elm->be_len = 1;

	ber_link_elements(prev, elm);

	return elm;
}

int
ber_get_boolean(struct ber_element *elm, int *b)
{
	if (elm->be_encoding != BER_TYPE_BOOLEAN)
		return -1;

	*b = !(elm->be_numeric == 0);
	return 0;
}

struct ber_element *
ber_add_string(struct ber_element *prev, const char *string)
{
	return ber_add_nstring(prev, string, strlen(string));
}

struct ber_element *
ber_add_nstring(struct ber_element *prev, const char *string0, size_t len)
{
	struct ber_element *elm;
	char *string;

	if ((string = calloc(1, len + 1)) == NULL)
		return NULL;
	if ((elm = ber_get_element(BER_TYPE_OCTETSTRING)) == NULL) {
		free(string);
		return NULL;
	}

	bcopy(string0, string, len);
	elm->be_val = string;
	elm->be_len = len;
	elm->be_free = 1;		/* free string on cleanup */

	ber_link_elements(prev, elm);

	return elm;
}

int
ber_get_string(struct ber_element *elm, char **s)
{
	if (elm->be_encoding != BER_TYPE_OCTETSTRING)
		return -1;

	*s = elm->be_val;
	return 0;
}

int
ber_get_nstring(struct ber_element *elm, void **p, size_t *len)
{
	if (elm->be_encoding != BER_TYPE_OCTETSTRING)
		return -1;

	*p = elm->be_val;
	*len = elm->be_len;
	return 0;
}

struct ber_element *
ber_add_bitstring(struct ber_element *prev, const void *v0, size_t len)
{
	struct ber_element *elm;
	void *v;

	if ((v = calloc(1, len)) == NULL)
		return NULL;
	if ((elm = ber_get_element(BER_TYPE_BITSTRING)) == NULL) {
		free(v);
		return NULL;
	}

	bcopy(v0, v, len);
	elm->be_val = v;
	elm->be_len = len;
	elm->be_free = 1;		/* free string on cleanup */

	ber_link_elements(prev, elm);

	return elm;
}

int
ber_get_bitstring(struct ber_element *elm, void **v, size_t *len)
{
	if (elm->be_encoding != BER_TYPE_BITSTRING)
		return -1;

	*v = elm->be_val;
	*len = elm->be_len;
	return 0;
}

struct ber_element *
ber_add_null(struct ber_element *prev)
{
	struct ber_element *elm;

	if ((elm = ber_get_element(BER_TYPE_NULL)) == NULL)
		return NULL;

	ber_link_elements(prev, elm);

	return elm;
}

int
ber_get_null(struct ber_element *elm)
{
	if (elm->be_encoding != BER_TYPE_NULL)
		return -1;

	return 0;
}

struct ber_element *
ber_add_eoc(struct ber_element *prev)
{
	struct ber_element *elm;

	if ((elm = ber_get_element(BER_TYPE_EOC)) == NULL)
		return NULL;

	ber_link_elements(prev, elm);

	return elm;
}

int
ber_get_eoc(struct ber_element *elm)
{
	if (elm->be_encoding != BER_TYPE_EOC)
		return -1;

	return 0;
}

size_t
ber_oid2ber(struct ber_oid *o, u_int8_t *buf, size_t len)
{
	u_int32_t	 v;
	u_int		 i, j = 0, k;

	if (o->bo_n < BER_MIN_OID_LEN || o->bo_n > BER_MAX_OID_LEN ||
	    o->bo_id[0] > 2 || o->bo_id[1] > 40)
		return (0);

	v = (o->bo_id[0] * 40) + o->bo_id[1];
	for (i = 2, j = 0; i <= o->bo_n; v = o->bo_id[i], i++) {
		for (k = 28; k >= 7; k -= 7) {
			if (v >= (u_int)(1 << k)) {
				if (len)
					buf[j] = v >> k | BER_TAG_MORE;
				j++;
			}
		}
		if (len)
			buf[j] = v & BER_TAG_TYPE_MASK;
		j++;
	}

	return (j);
}

int
ber_string2oid(const char *oidstr, struct ber_oid *o)
{
	char			*sp, *p, str[BUFSIZ];
	const char		*errstr;

	if (strlcpy(str, oidstr, sizeof(str)) >= sizeof(str))
		return (-1);
	bzero(o, sizeof(*o));

	/* Parse OID strings in the common forms n.n.n, n_n_n_n, or n-n-n */
	for (p = sp = str; p != NULL; sp = p) {
		if ((p = strpbrk(p, "._-")) != NULL)
			*p++ = '\0';
		o->bo_id[o->bo_n++] = strtonum(sp, 0, UINT_MAX, &errstr);
		if (errstr || o->bo_n > BER_MAX_OID_LEN)
			return (-1);
	}

	return (0);
}

struct ber_element *
ber_add_oid(struct ber_element *prev, struct ber_oid *o)
{
	struct ber_element	*elm;
	u_int8_t		*buf;
	size_t			 len;

	if ((elm = ber_get_element(BER_TYPE_OBJECT)) == NULL)
		return (NULL);

	if ((len = ber_oid2ber(o, NULL, 0)) == 0)
		goto fail;

	if ((buf = calloc(1, len)) == NULL)
		goto fail;

	elm->be_val = buf;
	elm->be_len = len;
	elm->be_free = 1;

	if (ber_oid2ber(o, buf, len) != len)
		goto fail;

	ber_link_elements(prev, elm);

	return (elm);

 fail:
	ber_free_elements(elm);
	return (NULL);
}

struct ber_element *
ber_add_noid(struct ber_element *prev, struct ber_oid *o, int n)
{
	struct ber_oid		 no;

	if (n > BER_MAX_OID_LEN)
		return (NULL);
	no.bo_n = n;
	bcopy(&o->bo_id, &no.bo_id, sizeof(no.bo_id));

	return (ber_add_oid(prev, &no));
}

struct ber_element *
ber_add_oidstring(struct ber_element *prev, const char *oidstr)
{
	struct ber_oid		 o;

	if (ber_string2oid(oidstr, &o) == -1)
		return (NULL);

	return (ber_add_oid(prev, &o));
}

int
ber_get_oid(struct ber_element *elm, struct ber_oid *o)
{
	u_int8_t	*buf;
	size_t		 len, i = 0, j = 0;

	if (elm->be_encoding != BER_TYPE_OBJECT)
		return (-1);

	buf = elm->be_val;
	len = elm->be_len;

	if (!buf[i])
		return (-1);

	bzero(o, sizeof(*o));
	o->bo_id[j++] = buf[i] / 40;
	o->bo_id[j++] = buf[i++] % 40;
	for (; i < len && j < BER_MAX_OID_LEN; i++) {
		o->bo_id[j] = (o->bo_id[j] << 7) + (buf[i] & ~0x80);
		if (buf[i] & 0x80)
			continue;
		j++;
	}
	o->bo_n = j;

	return (0);
}

struct ber_element *
ber_printf_elements(struct ber_element *ber, char *fmt, ...)
{
	va_list			 ap;
	int			 d, class;
	size_t			 len;
	unsigned long		 type;
	long long		 i;
	char			*s;
	void			*p;
	struct ber_oid		*o;
	struct ber_element	*sub = ber, *e;

	va_start(ap, fmt);
	while (*fmt) {
		switch (*fmt++) {
		case 'B':
			p = va_arg(ap, void *);
			len = va_arg(ap, size_t);
			ber = ber_add_bitstring(ber, p, len);
			break;
		case 'b':
			d = va_arg(ap, int);
			ber = ber_add_boolean(ber, d);
			break;
		case 'd':
			d = va_arg(ap, int);
			ber = ber_add_integer(ber, d);
			break;
		case 'e':
			e = va_arg(ap, struct ber_element *);
			ber_link_elements(ber, e);
			break;
		case 'E':
			i = va_arg(ap, long long);
			ber = ber_add_enumerated(ber, i);
			break;
		case 'i':
			i = va_arg(ap, long long);
			ber = ber_add_integer(ber, i);
			break;
		case 'O':
			o = va_arg(ap, struct ber_oid *);
			ber = ber_add_oid(ber, o);
			break;
		case 'o':
			s = va_arg(ap, char *);
			ber = ber_add_oidstring(ber, s);
			break;
		case 's':
			s = va_arg(ap, char *);
			ber = ber_add_string(ber, s);
			break;
		case 't':
			class = va_arg(ap, int);
			type = va_arg(ap, unsigned long);
			ber_set_header(ber, class, type);
			break;
		case 'x':
			s = va_arg(ap, char *);
			len = va_arg(ap, size_t);
			ber = ber_add_nstring(ber, s, len);
			break;
		case '0':
			ber = ber_add_null(ber);
			break;
		case '{':
			ber = sub = ber_add_sequence(ber);
			break;
		case '(':
			ber = sub = ber_add_set(ber);
			break;
		case '}':
		case ')':
			ber = sub;
			break;
		case '.':
			ber = ber_add_eoc(ber);
			break;
		default:
			break;
		}
	}
	va_end(ap);

	return (ber);
}

int
ber_scanf_elements(struct ber_element *ber, char *fmt, ...)
{
#define _MAX_SEQ		 128
	va_list			 ap;
	int			*d, level = -1;
	unsigned long		*t;
	long long		*i;
	void			**ptr;
	size_t			*len, ret = 0, n = strlen(fmt);
	char			**s;
	off_t			*pos;
	struct ber_oid		*o;
	struct ber_element	*parent[_MAX_SEQ], **e;

	bzero(parent, sizeof(struct ber_element *) * _MAX_SEQ);

	va_start(ap, fmt);
	while (*fmt) {
		switch (*fmt++) {
		case 'B':
			ptr = va_arg(ap, void **);
			len = va_arg(ap, size_t *);
			if (ber_get_bitstring(ber, ptr, len) == -1)
				goto fail;
			ret++;
			break;
		case 'b':
			d = va_arg(ap, int *);
			if (ber_get_boolean(ber, d) == -1)
				goto fail;
			ret++;
			break;
		case 'e':
			e = va_arg(ap, struct ber_element **);
			*e = ber;
			ret++;
			continue;
		case 'E':
			i = va_arg(ap, long long *);
			if (ber_get_enumerated(ber, i) == -1)
				goto fail;
			ret++;
			break;
		case 'i':
			i = va_arg(ap, long long *);
			if (ber_get_integer(ber, i) == -1)
				goto fail;
			ret++;
			break;
		case 'o':
			o = va_arg(ap, struct ber_oid *);
			if (ber_get_oid(ber, o) == -1)
				goto fail;
			ret++;
			break;
		case 'S':
			ret++;
			break;
		case 's':
			s = va_arg(ap, char **);
			if (ber_get_string(ber, s) == -1)
				goto fail;
			ret++;
			break;
		case 't':
			d = va_arg(ap, int *);
			t = va_arg(ap, unsigned long *);
			*d = ber->be_class;
