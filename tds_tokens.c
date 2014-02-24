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

/* Implementation file for handling various TDS tokens. */

#include "tds_buf.h"
#include "tds_log.h"
#include "tds_tokens.h"
#include "utils.h"

#define TOKEN_ENVCHANGE 0xe3

enum {
	EC_DATABASE = 1
};

static void handle_envchange(struct connection *conn, uint16_t token_len);

/* 2.2.7.8 */
static void
handle_envchange(struct connection *conn, uint16_t token_len)
{
	uint8_t change_type;

	tds_debug(0, "+ENVCHANGE: %d bytes\n", token_len);

	change_type = buf_get8(conn);
	switch (change_type) {
	case EC_DATABASE:
		tds_debug(0, "  Change: Database\n");
		break;
	default:
		tds_debug(0, "  Change: %d (unknown)\n", change_type);
	}

	conn->b_offset += token_len;

}

void
handle_tokens(struct connection *conn, size_t nread)
{
	dump_hex(conn->buffer, nread);

	/* Start at 0x08 */
	conn->b_offset = 0x08;
	tds_debug(0, "Type = 0x%02x\n", conn->buffer[conn->b_offset]);

	while (conn->b_offset < nread) {
		uint8_t token_type;
		uint16_t token_len;

		token_type = buf_get8(conn);
		switch (token_type) {
		case TOKEN_ENVCHANGE:
			token_len = buf_get16_le(conn);
			handle_envchange(conn, token_len);
			break;
		default:
			break;
		}
	}
}


