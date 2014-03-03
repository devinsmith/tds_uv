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
#include <string.h>
#include <stdlib.h>

#include "tds_buf.h"
#include "tds_log.h"
#include "tds_tokens.h"
#include "utils.h"

#define TOKEN_COLMETADATA 0x81
#define TOKEN_ERROR 0xaa
#define TOKEN_INFO 0xab
#define TOKEN_LOGINACK 0xad
#define TOKEN_ENVCHANGE 0xe3
#define TOKEN_DONE 0xfd

enum {
	EC_DATABASE = 1,
	EC_LANGUAGE = 2,
	EC_PKTSIZE = 4,
	EC_COLLATION = 7
};

static void handle_envchange(struct connection *conn, uint16_t token_len);
static void handle_message(struct connection *conn, const char *type, uint16_t token_len);
static void handle_loginack(struct connection *conn, uint16_t token_len);
static void handle_done(struct connection *conn);


static void
handle_done(struct connection *conn)
{
	uint16_t status;
	uint16_t current_command;
	uint32_t row_count;

	status = buf_get16_le(conn);
	current_command = buf_get16_le(conn);
	row_count = buf_get32_le(conn);
	tds_debug(0, "Done, status %d\n", status);

	if (status == 0) {
		conn->stage = TDS_LOGGED_IN;
	}
}

static void
handle_message(struct connection *conn, const char *type, uint16_t token_len)
{
	uint32_t number;
	uint8_t state;
	uint8_t severity;
	uint16_t text_len;
	char text[512];
	uint8_t sname_len;
	char server_name[256];
	uint8_t pname_len;
	char proc_name[256];
	uint16_t line;

	*text = *server_name = *proc_name = 0;

	tds_debug(0, "+%s: %d\n", type, token_len);
	number = buf_get32_le(conn);
	state = buf_get8(conn);
	severity = buf_get8(conn);
	text_len = buf_get16_le(conn) * 2;
	ucs2_to_str(buf_getraw(conn, text_len), text_len, text, sizeof(text));
	sname_len = buf_get8(conn) * 2;
	ucs2_to_str(buf_getraw(conn, sname_len), sname_len, server_name, sizeof(server_name));
	pname_len = buf_get8(conn) * 2;
	ucs2_to_str(buf_getraw(conn, pname_len), pname_len, proc_name, sizeof(proc_name));
	line = buf_get16_le(conn);

	if (number > 0 && severity > 0) {
		tds_debug(0, "Msg %d, Level %d, State %d\n", number, severity, state);
		tds_debug(0, "Server '%s'", server_name);
		if (*proc_name != '\0')
			tds_debug(0, ", Procedure '%s'", proc_name);
		if (line > 0)
			tds_debug(0, ", Line %d\n", line);
		tds_debug(0, "%s\n", text);
	} else {
		tds_debug(0, "%s\n", text);
	}
}

/* 2.2.7.11 */
static void
handle_loginack(struct connection *conn, uint16_t token_len)
{
	uint8_t interface;
	uint32_t tds_version;
	uint8_t len;
	char prog_name[256];
	uint8_t major, minor;
	uint16_t build;

	tds_debug(0, "+LOGINACK: %d bytes\n", token_len);
	interface = buf_get8(conn);
	tds_version = buf_get32_le(conn);
	tds_debug(0, "Version: %x\n", tds_version);
	len = buf_get8(conn) * 2;
	ucs2_to_str(buf_getraw(conn, len), len, prog_name, sizeof(prog_name));
	tds_debug(0, "Prog: %s\n", prog_name);
	major = buf_get8(conn);
	minor = buf_get8(conn);
	build = buf_get16_le(conn);
	tds_debug(0, "Major: %d Minor: %d Build: %d\n", major, minor, build);
}

/* 2.2.7.8 */
static void
handle_envchange(struct connection *conn, uint16_t token_len)
{
	uint8_t change_type;
	char *dest;
	char old[256];
	uint8_t len;

	change_type = buf_get8(conn);
	tds_debug(0, "+ENVCHANGE: (%d) %d bytes\n", change_type, token_len);

	if (change_type == EC_COLLATION) {
		unsigned char o_col[5];

		/* Grab new collation info */
		len = buf_get8(conn);
		memcpy(conn->env.collation, buf_getraw(conn, len), len);

		/* TODO What to do with old collation info? */
		len = buf_get8(conn);
		memcpy(o_col, buf_getraw(conn, len), len);
		return;
	}

	if (change_type != EC_DATABASE && change_type != EC_LANGUAGE &&
	    change_type != EC_PKTSIZE) {
		tds_debug(0, "  Change: %d (unknown)\n", change_type);
		return;
	}

	if (change_type == EC_DATABASE) {
		dest = conn->env.database;
	} else if (change_type == EC_LANGUAGE) {
		dest = conn->env.language;
	}

	len = buf_get8(conn) * 2;
	dest = malloc(len + 1);
	ucs2_to_str(buf_getraw(conn, len), len, dest, len);
	dest[len] = '\0';

	old[0] = '\0';
	len = buf_get8(conn) * 2;
	ucs2_to_str(buf_getraw(conn, len), len, old, sizeof(old));
	tds_debug(0, "%s -> %s\n", old, dest);

	if (change_type == EC_PKTSIZE) {
		conn->env.packet_size = atoi(dest);
		free(dest);
	}
}

/* 2.2.7.4 */
void
process_colmetadata(struct connection *conn, uint16_t token_len)
{
	uint16_t user_type;
	uint16_t flags;
	uint8_t col_type;
	tds_debug(0, "+COLMETADATA: %d\n", token_len);

	user_type = buf_get16_le(conn);
	flags = buf_get16_le(conn);
	col_type = buf_get8(conn);
	tds_debug(0, "Col: user type: %d, flags: %d, col_type: %d\n", user_type,
	    flags, col_type);
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
		case TOKEN_COLMETADATA:
			token_len = buf_get16_le(conn);
			process_colmetadata(conn, token_len);
			conn->stage = TDS_QUERY;
			break;
		case TOKEN_ENVCHANGE:
			token_len = buf_get16_le(conn);
			handle_envchange(conn, token_len);
			break;
		case TOKEN_ERROR:
			token_len = buf_get16_le(conn);
			handle_message(conn, "TOKEN_ERROR", token_len);
			break;
		case TOKEN_INFO:
			token_len = buf_get16_le(conn);
			handle_message(conn, "TOKEN_INFO", token_len);
			break;
		case TOKEN_LOGINACK:
			token_len = buf_get16_le(conn);
			handle_loginack(conn, token_len);
			break;
		case TOKEN_DONE:
			handle_done(conn);
			break;
		default:
			tds_debug(0, "unknown type %d\n", token_type);
			break;
		}
	}
}

void
fire_query(struct connection *conn)
{
	uv_write_t *write_req = malloc(sizeof(uv_write_t) + sizeof(uv_buf_t));
	uv_buf_t *pkt = (uv_buf_t *)(write_req + 1);
	unsigned char unicode_buf[1024];

	buf_tds_init(pkt, 256, 0x1 /* SQL Batch */, TDS_EOM);

	buf_addraw(pkt, str_to_ucs2("SELECT 1", unicode_buf,
	    sizeof(unicode_buf)), strlen("SELECT 1") * 2);

	/* Write header */
	buf_set_hdr(pkt);
	tds_debug(0, "pkt len: %d\n", (int)pkt->len);
	dump_hex(pkt->base, pkt->len);

	uv_write(write_req, conn->tcp_handle, pkt, 1, after_write);
}
