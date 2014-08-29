/*
 * Copyright (c) 2013 Devin Smith <devin@devinsmith.net>
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tds_log.h"
#include "utils.h"

unsigned char *
str_to_ucs2(const char *s, unsigned char *d, size_t len)
{
	size_t p;

	for (p = 0; *s && p < len - 1; ++s) {
		if (p < len - 2) {
			d[p++] = *s;
			d[p++] = '\0';
		}
	}
	return d;
}

void
ucs2_to_str(unsigned char *s, size_t slen, char *d, size_t dlen)
{
	int i;

	if (slen == 0) return;

	/* Skip every 2 bytes */
	for (i = 0; i < slen && i < dlen - 1; i += 2) {
		*d++ = s[i];
	}
	*d = '\0';
}

void
dump_hex(int lvl, void *vp, size_t len)
{
	char linebuf[80];
	int i;
	int linebuf_dirty = 0;
	unsigned char *p = (unsigned char *)vp;

	memset(linebuf, ' ', sizeof(linebuf));
	linebuf[70] = '\0';

	for (i = 0; i < len; i++) {
		int x = i % 16;
		int ch = (unsigned)p[i];
		char hex[20];

		if (x >= 8)
			x = x * 3 + 1;
		else
			x = x * 3;
		snprintf(hex, sizeof(hex), "%02x", ch);
		linebuf[x] = hex[0];
		linebuf[x + 1] = hex[1];

		if (isprint(ch))
			linebuf[52 + (i % 16)] = ch;
		else
			linebuf[52 + (i % 16)] = '.';

		linebuf_dirty = 1;
		if (!((i + 1) % 16)) {
			tds_debug(lvl, "%s\n", linebuf);
			memset(linebuf, ' ', sizeof(linebuf));
			linebuf[70] = '\0';
			linebuf_dirty = 0;
		}
	}
	if (linebuf_dirty == 1)
		tds_debug(lvl, "%s\n", linebuf);
}

/**
 * tds7_crypt_pass() -- 'encrypt' TDS 7.0 style passwords.
 * the calling function is responsible for ensuring crypt_pass is at least·
 * 'len' characters
 */
unsigned char *
tds7_crypt_pass(const unsigned char *clear_pass, size_t len,
    unsigned char *crypt_pass)
{
	size_t i;

	for (i = 0; i < len; i++)
		crypt_pass[i] = ((clear_pass[i] << 4) | (clear_pass[i] >> 4)) ^ 0xA5;
	return crypt_pass;
}
