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

#ifndef __UTILS_H__
#define __UTILS_H__

void dump_hex(void *vp, size_t len);
unsigned char *str_to_ucs2(const char *s, unsigned char *d, size_t len);
void ucs2_to_str(unsigned char *s, size_t slen, char *d, size_t dlen);

/* From FreeTDS */
unsigned char *tds7_crypt_pass(const unsigned char *clear_pass, size_t len,
    unsigned char *crypt_pass);


#endif /* __UTILS_H__ */

