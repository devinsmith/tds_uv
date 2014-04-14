/* Copyright (C) 2003-2005, Claudio Leite
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the BSF Software Project nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */

/* This code is based on Claudio Leite's packet.c file inside the
 * imcomm module of his bsflite program. Claudio states that his code was
 * inspired by libfaim's (now defunct) bstream (binary stream)
 * implementation.
 */

#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "tds_buf.h"

#define MAX_SIZE	16384

void
buf_raw_init(uv_buf_t *buf, size_t len)
{
	if (buf == NULL)
		return;

	buf->base = malloc(len);
	if (buf->base == NULL) {
		return;
	}

	buf->len = 0;
}

/* Create a standard TDS packet header.
 * Many of the fields are documented in the spec (2.2.3.1).
 * The length of the packet is set again by the caller via the
 * buf_set_hdr function. */
void
buf_tds_init(uv_buf_t *buf, size_t len, uint8_t type, uint8_t sta_type)
{
	buf_raw_init(buf, len + 8);
	buf_add8(buf, type); /* TDS Packet type (2.2.3.1.1) */
	buf_add8(buf, sta_type); /* status message */
	buf_add16(buf, 0); /* length in big endian (filled later) */
	buf_add16(buf, 0); /* SPID */
	buf_add8(buf, 1); /* Packet Id (ignored by Microsoft implementation) */
	buf_add8(buf, 0); /* Window Id (always 0) */
}

void
buf_addraw(uv_buf_t *p, const unsigned char *bytes, size_t len)
{
	memcpy(p->base + p->len, bytes, len);
	p->len += len;
}

void
buf_addzero(uv_buf_t *p, int num_zeros)
{
	memset(p->base + p->len, 0, num_zeros);
	p->len += num_zeros;
}

void
buf_addstring(uv_buf_t *p, const char *bytes)
{
	uint32_t len;

	len = strlen(bytes);
	buf_addraw(p, (unsigned char *) bytes, len);
}

void
buf_add8(uv_buf_t *p, uint8_t val)
{
	p->base[p->len++] = val;
}

void
buf_add16_le(uv_buf_t *p, uint16_t val)
{
	p->base[p->len++] = (val & 0xff);
	p->base[p->len++] = (val & 0xff00) >> 8;
}

void
buf_add16(uv_buf_t *p, uint16_t val)
{
	p->base[p->len++] = (val & 0xff00) >> 8;
	p->base[p->len++] = (val & 0xff);
}

void
buf_add32_le(uv_buf_t *p, uint32_t val)
{
	p->base[p->len++] = (val & 0xff);
	p->base[p->len++] = (val & 0xff00) >> 8;
	p->base[p->len++] = (val & 0xff0000) >> 16;
	p->base[p->len++] = (val & 0xff000000) >> 24;
}

void
buf_add32(uv_buf_t *p, uint32_t val)
{
	p->base[p->len++] = (val & 0xff000000) >> 24;
	p->base[p->len++] = (val & 0xff0000) >> 16;
	p->base[p->len++] = (val & 0xff00) >> 8;
	p->base[p->len++] = (val & 0xff);
}

void
buf_set_hdr(uv_buf_t *p)
{
	p->base[2] = (p->len & 0xff00) >> 8;
	p->base[3] = (p->len & 0xff);
}

void
buf_free(uv_buf_t *p)
{
	free(p->base);
}

uint8_t
buf_get8(struct connection *conn)
{
	return conn->buffer[conn->b_offset++];
}

uint16_t
buf_get16(struct connection *conn)
{
	uint16_t ret;

	ret = conn->buffer[conn->b_offset++] << 8;
	ret += conn->buffer[conn->b_offset++];

	return ret;
}

uint16_t
buf_get16_le(struct connection *conn)
{
	uint16_t ret;

	ret = conn->buffer[conn->b_offset++];
	ret += conn->buffer[conn->b_offset++] << 8;

	return ret;
}

uint32_t
buf_get32(struct connection *conn)
{
	uint32_t ret;

	ret = conn->buffer[conn->b_offset++] << 24;
	ret += conn->buffer[conn->b_offset++] << 16;
	ret += conn->buffer[conn->b_offset++] << 8;
	ret += conn->buffer[conn->b_offset++];

	return ret;
}

uint32_t
buf_get32_le(struct connection *conn)
{
	uint32_t ret;

	ret = conn->buffer[conn->b_offset++];
	ret += conn->buffer[conn->b_offset++] << 8;
	ret += conn->buffer[conn->b_offset++] << 16;
	ret += conn->buffer[conn->b_offset++] << 24;

	return ret;
}

unsigned char *
buf_getraw(struct connection *conn, size_t advance)
{
	unsigned char *ret = conn->buffer + conn->b_offset;
	conn->b_offset += advance;
	return ret;
}
