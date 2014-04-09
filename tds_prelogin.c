/*
 * Copyright (c) 2014 Devin Smith <devin@devinsmith.net>
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

/* Implementation for TDS Prelogin packet (2.2.6.4). */
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "tds_buf.h"
#include "tds_log.h"
#include "tds_prelogin.h"
#include "utils.h"

void
send_prelogin(uv_stream_t *stream, struct connection *conn)
{
	uv_write_t *write_req = malloc(sizeof(uv_write_t) + sizeof(uv_buf_t));
	uv_buf_t *pkt = (uv_buf_t *)(write_req + 1);
	size_t token_offset;
	size_t data_offset;
	unsigned char *size_ptr;

	/* Packet header is always 8 bytes */
	buf_tds_init(pkt, 128, TDS_PRELOGIN, TDS_EOM);

	/* keep a pointer to the start of tokens */
	token_offset = pkt->len;

	/* Each token has the following components:
	 * TokenType - 1 byte
	 * TokenDataOffset - 2 bytes (big endian)
	 *  -- TokenDataOffset is calculated dynamically below.
	 * TokenDataLength - 2 bytes (big endian)
	 */

	buf_add8(pkt, 0); /* Version */
	buf_add16(pkt, 0); /* Start position (filled in below)*/
	buf_add16(pkt, 6); /* Length */

	buf_add8(pkt, 1); /* Encryption */
	buf_add16(pkt, 0);
	buf_add16(pkt, 1); /* 1 byte */

	buf_add8(pkt, 2); /* Instance option */
	buf_add16(pkt, 0); /* starting offset */
	buf_add16(pkt, strlen(conn->instance) + 1);

	buf_add8(pkt, 3); /* thread id */
	buf_add16(pkt, 0);
	buf_add16(pkt, 4); /* pid is 4 bytes */

	buf_add8(pkt, 0xff); /* End of tokens */
	data_offset = pkt->len - 8; /* 8 is size of header */

	/* Loop through each token and set the TokenDataOffset
	 * correctly. The token terminator is 0xff. */
	size_ptr = (unsigned char *)pkt->base + token_offset;
	while (*size_ptr != 0xff) {
		unsigned short token_len;

		/* Skip the TokenType byte */
		size_ptr++;

		/* Overwrite the TokenDataOffset */
		*size_ptr++ = (data_offset & 0xff00) >> 8;
		*size_ptr++ = (data_offset & 0xff);

		/* Read the TokenDataLength and update data offset
		 * as we loop through the tokens */
		token_len = *size_ptr++ << 8;
		token_len += *size_ptr++;

		data_offset += token_len;
	}

	/* TOKEN 0 */
	/* UL_VERSION:
	 * Major version: 1 byte
	 * Minor version: 1 byte
	 * Build Number: 2 bytes */

	/* According to the FreeTDS source code:
	 * TDS 7.2 and higher are sent with: 9.0.0000 */
	/* TDS 7.1 and lower are sent with:  8.0.0341 */
	/* The MS-TDF.pdf sample packet sends 9.0.0000 */
	buf_add8(pkt, 9);
	buf_add8(pkt, 0);
	buf_add16(pkt, 0);

	/* US_SUBBUILD (I've never seen a non-zero value here.) */
	buf_add16(pkt, 0);

	/* TOKEN 1 (ENCRYPTION) */
	buf_add8(pkt, 2); /* Encryption not currently supported. */

	/* TOKEN 2 (INSTOPT) */
	buf_addstring(pkt, conn->instance);
	buf_add8(pkt, 0); /* terminating byte */

	/* TOKEN 3 (THREADID) */
	buf_add32(pkt, 0); /* getpid? */

	/* Write header */
	buf_set_hdr(pkt);

	dump_hex(pkt->base, pkt->len);

	uv_write(write_req, stream, pkt, 1, after_write);
}


