/*	$OpenBSD: ber.h,v 1.8 2012/09/17 16:30:34 reyk Exp $ */

/*
 * Copyright (c) 2007, 2012 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006, 2007 Claudio Jeker <claudio@openbsd.org>
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

#ifndef _BER_H
#define _BER_H

struct ber_element {
	struct ber_element	*be_next;
	unsigned long		 be_type;
	unsigned long		 be_encoding;
	size_t			 be_len;
	off_t			 be_offs;
	int			 be_free;
	u_int8_t		 be_class;
	void			(*be_cb)(void *, size_t);
	void			*be_cbarg;
	union {
		struct ber_element	*bv_sub;
		void			*bv_val;
		long long		 bv_numeric;
	} be_union;
#define be_sub		be_union.bv_sub
#define be_val		be_union.bv_val
#define be_numeric	be_union.bv_numeric
};

struct ber {
	int	 fd;
	off_t	 br_offs;
	u_char	*br_wbuf;
	u_char	*br_wptr;
	u_char	*br_wend;
	u_char	*br_rbuf;
	u_char	*br_rptr;
	u_char	*br_rend;

	unsigned long	(*br_application)(struct ber_element *);
};

/* well-known ber_element types */
#define BER_TYPE_DEFAULT	((unsigned long)-1)
#define BER_TYPE_EOC		0
#define BER_TYPE_BOOLEAN	1
