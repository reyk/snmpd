/*	$OpenBSD: usm.c,v 1.6 2013/01/24 09:30:27 gerhard Exp $	*/

/*
 * Copyright (c) 2012 GeNUA mbH
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

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#ifdef DEBUG
#include <assert.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "snmpd.h"
#include "mib.h"

extern struct snmpd	*env;

SLIST_HEAD(, usmuser)	usmuserlist;

const EVP_MD		*usm_get_md(enum usmauth);
const EVP_CIPHER	*usm_get_cipher(enum usmpriv);
void			 usm_cb_digest(void *, size_t);
int			 usm_valid_digest(struct snmp_message *, off_t, char *,
			    size_t);
struct ber_element	*usm_decrypt(struct snmp_message *,
			    struct ber_element *);
ssize_t			 usm_crypt(struct snmp_message *, u_char *, int,
			    u_char *, int);
char			*usm_passwd2key(const EVP_MD *, char *, int *);

void
usm_generate_keys(void)
{
	struct usmuser	*up;
	const EVP_MD	*md;
	char		*key;
	int		 len;

	SLIST_FOREACH(up, &usmuserlist, uu_next) {
		if ((md = usm_get_md(up->uu_auth)) == NULL)
			continue;

		/* convert auth password to key */
		len = 0;
		key = usm_passwd2key(md, up->uu_authkey, &len);
		free(up->uu_authkey);
		up->uu_authkey = key;
		up->uu_authkeylen = len;

		/* optionally convert privacy password to key */
		if (up->uu_priv != PRIV_NONE) {
			arc4random_buf(&up->uu_salt, sizeof(up->uu_salt));

			len = SNMP_CIPHER_KEYLEN;
			key = usm_passwd2key(md, up->uu_privkey, &len);
			free(up->uu_privkey);
			up->uu_privkey = key;
