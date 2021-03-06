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

#include "constants.h"
#include "tds_buf.h"
#include "tds_log.h"
#include "tds_tokens.h"
#include "tds_types.h"
#include "utils.h"

#define TOKEN_RETURNSTATUS 0x79
#define TOKEN_COLMETADATA 0x81
#define TOKEN_ERROR 0xaa
#define TOKEN_INFO 0xab
#define TOKEN_LOGINACK 0xad
#define TOKEN_ROW 0xd1
#define TOKEN_ENVCHANGE 0xe3
#define TOKEN_DONE 0xfd
#define TOKEN_DONEPROC 0xfe
#define TOKEN_DONEINPROC 0xff

enum {
	EC_DATABASE = 1,
	EC_LANGUAGE = 2,
	EC_PKTSIZE = 4,
	EC_COLLATION = 7
};

#define DONE_FINAL 0x00
#define DONE_MORE  0x01
#define DONE_ERROR 0x02

static void handle_envchange(struct connection *conn, uint16_t token_len);
static void handle_message(struct connection *conn, int type, uint16_t token_len);
static void handle_loginack(struct connection *conn, uint16_t token_len);
static void handle_done(struct connection *conn);

/* Token: DONE (2.2.7.5) */
static void
handle_done(struct connection *conn)
{
	uint16_t status;
	uint32_t row_count;

	status = buf_get16_le(conn);
	/* The next unsigned short (16 bits) contains a token of the current
	 * SQL statement, but we don't use it yet. */
	buf_get16_le(conn);

	row_count = buf_get32_le(conn);
	tds_debug(0, "Done, status %d, %d rows affected\n", status, row_count);

	/* Check if this is the final done before calling any callbacks */
	if (status == DONE_FINAL) {
		if (conn->stage == TDS_LOGGING_IN) {
			/* Login succeeded, move to IDLE state, ready for queries */
			conn->stage = TDS_IDLE;
		} else if (conn->stage == TDS_BUSY) {
			conn->stage = TDS_IDLE;
			free(conn->sql);
			conn->sql = NULL;
			free(conn->procname);
			conn->procname = NULL;
		}
	} else if (status == DONE_ERROR) {
		conn->stage = TDS_IDLE;
	}

}

static void
handle_message(struct connection *conn, int type, uint16_t token_len)
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

	if (type == TOKEN_ERROR)
		tds_debug(0, "+TOKEN_ERROR: %d\n", token_len);
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

	/* Error handler */
	if (number > 0 && severity > 0) {
		/* Call a handler / callback and give the caller some ability to
		 * dictate what should happen with errors */
		if (conn->on_error != NULL) {
			conn->on_error(conn, number, severity, state, server_name, proc_name,
			    line, text);
		} else {
			tds_debug(0, "Msg %d, Level %d, State %d\n", number, severity, state);
			tds_debug(0, "Server '%s'", server_name);
			if (*proc_name != '\0')
				tds_debug(0, ", Procedure '%s'", proc_name);
			if (line > 0)
				tds_debug(0, ", Line %d\n", line);
			tds_debug(0, "%s\n", text);
			exit(1);
		}
	} else {
		/* Info handler */
		tds_debug(0, "%s\n", text);
	}
}

/* 2.2.7.11 */
static void
handle_loginack(struct connection *conn, uint16_t token_len)
{
	uint8_t interface_type;
	uint32_t tds_version;
	uint8_t len;
	char prog_name[256];
	uint8_t major, minor;
	uint16_t build;

	tds_debug(0, "+LOGINACK: %d bytes\n", token_len);
	interface_type = buf_get8(conn);
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
	char old[256];
	uint8_t len;

	change_type = buf_get8(conn);

	if (change_type == EC_COLLATION) {
		unsigned char o_col[5];

		/* Grab new collation info */
		len = buf_get8(conn);
		memcpy(conn->env.collation, buf_getraw(conn, len), len);

		/* TODO What to do with old collation info? */
		len = buf_get8(conn);
		memcpy(o_col, buf_getraw(conn, len), len);
	} else if (change_type == EC_DATABASE) {
		free(conn->env.database);

		len = buf_get8(conn) * 2;
		conn->env.database = malloc(len + 1);
		ucs2_to_str(buf_getraw(conn, len), len, conn->env.database, len);
		conn->env.database[len] = '\0';

		old[0] = '\0';
		len = buf_get8(conn) * 2;
		ucs2_to_str(buf_getraw(conn, len), len, old, sizeof(old));
		tds_debug(1, "ENVCHANGE (EC_DATABASE): %s -> %s\n", old, conn->env.database);
		if (strcmp(conn->env.database, conn->database) == 0)
			conn->need_use = 0;

	} else if (change_type == EC_LANGUAGE) {
		free(conn->env.language);

		len = buf_get8(conn) * 2;
		conn->env.language = malloc(len + 1);
		ucs2_to_str(buf_getraw(conn, len), len, conn->env.language, len);
		conn->env.language[len] = '\0';

		old[0] = '\0';
		len = buf_get8(conn) * 2;
		ucs2_to_str(buf_getraw(conn, len), len, old, sizeof(old));
		tds_debug(1, "ENVCHANGE (EC_LANGUAGE): %s -> %s\n", old, conn->env.language);
	} else if (change_type == EC_PKTSIZE) {
		len = buf_get8(conn) * 2;
		ucs2_to_str(buf_getraw(conn, len), len, old, len);
		old[len] = '\0';
		conn->env.packet_size = atoi(old);

		old[0] = '\0';
		len = buf_get8(conn) * 2;
		ucs2_to_str(buf_getraw(conn, len), len, old, sizeof(old));
		tds_debug(1, "ENVCHANGE (EC_PKTSIZE): %s -> %d\n", old, conn->env.packet_size);
	} else {
		tds_debug(0, "+ENVCHANGE: (change type unknown: %d) %d bytes\n",
		    change_type, token_len);
	}
}

/* 2.2.7.4 */
void
process_colmetadata(struct connection *conn)
{
	uint16_t user_type;
	uint16_t flags;
	uint8_t col_type;
	uint16_t total_cols;
	unsigned int i;
	uint8_t colname_len;
	struct tds_row *row;

	total_cols = buf_get16_le(conn);

	tds_debug(0, "+COLMETADATA: Total cols: %d\n", total_cols);
	if (total_cols == 0xFFFF) {
		tds_debug(0, "No column meta data\n");
		total_cols = 0;
		return;
	}

	/* Free up previous result. */
	free(conn->result.cols);
	while ((row = TAILQ_FIRST(&conn->result.row_list))) {
		TAILQ_REMOVE(&conn->result.row_list, row, dbrows);
		for (i = 0; i < conn->result.ncols; i++) {
			if (row->columns[i].type == STRING_TYPE)
				free(row->columns[i].data.s);
		}
		free(row->columns);
		free(row);
	}

	conn->result.ncols = total_cols;
	conn->result.cols = calloc(total_cols, sizeof(struct tds_column));
	TAILQ_INIT(&conn->result.row_list);

	for (i = 0; i < total_cols; i++) {
		int column_len_size;
		uint32_t column_len;
		user_type = buf_get16_le(conn);
		flags = buf_get16_le(conn);
		col_type = buf_get8(conn);
		conn->result.cols[i].type = col_type;

		/* The next bytes of the packet determine how many bytes are used
		 * to represent the size of the length of the column. */
		column_len = 0;
		column_len_size = tds_get_size_by_type(col_type);
		if (column_len_size == 1) {
			column_len = buf_get8(conn);
		} else if (column_len_size == 2) {
			column_len = buf_get16_le(conn);
		} else if (column_len_size == 4) {
			column_len = buf_get32_le(conn);
		} else if (column_len_size == -1) {
			tds_debug(0, "Length for column type %d is unknown.\n", col_type);
			return;
		}

		conn->result.cols[i].len = column_len;

		if (col_type == TDS_BIGVARCHAR) {
			/* XXX: actually handle collation */
			buf_getraw(conn, 5);
		}

		/* Read column name */
		colname_len = buf_get8(conn) * 2;
		ucs2_to_str(buf_getraw(conn, colname_len), colname_len,
		    conn->result.cols[i].name, TDS_COLUMN_MAX_LEN);


		tds_debug(0, "Col: user type: %d, flags: %d, col_type: %d: %s\n", user_type,
	    flags, col_type, conn->result.cols[i].name);
	}
}

static void
handle_row(struct connection *conn)
{
	unsigned int i;
	uint32_t len;
	uint8_t bit;
	struct tds_row *row;

	row = malloc(sizeof(struct tds_row));
	row->columns = malloc(sizeof(struct tds_dbval) * conn->result.ncols);

	tds_debug(0, "Row\n");
	for (i = 0; i < conn->result.ncols; i++) {
		switch (conn->result.cols[i].type) {
		case TDS_BITN:
			len = buf_get8(conn);
			if (len == 1) {
				bit = buf_get8(conn);
				row->columns[i].type = INT4_TYPE;
				row->columns[i].data.i = bit;
			} else {
				row->columns[i].type = NULL_TYPE;
			}
			break;
		case TDS_INT4:
			row->columns[i].type = INT4_TYPE;
			row->columns[i].data.i = buf_get32_le(conn);
			break;
		case TDS_DATETIME:
			dump_hex(0, conn->buffer, 8);
			buf_getraw(conn, 8);
			break;
		case TDS_BIGVARCHAR:
			len = buf_get16_le(conn);
			row->columns[i].type = STRING_TYPE;
			row->columns[i].data.s = malloc(len + 1);
			memcpy(row->columns[i].data.s, buf_getraw(conn, len), len);
			row->columns[i].data.s[len] = '\0';
			break;
		default:
			tds_debug(0, "Unknown type! (%d)\n", conn->result.cols[i].type);
			break;
		}
	}
	TAILQ_INSERT_TAIL(&conn->result.row_list, row, dbrows);
	conn->result.nrows++;
}

void
handle_tokens(struct connection *conn, size_t nread)
{
	uint32_t ret;

	dump_hex(1, conn->buffer, nread);

	/* Start at 0x08 */
	conn->b_offset = 0x08;
	tds_debug(2, "Type = 0x%02x\n", conn->buffer[conn->b_offset]);

	while (conn->b_offset < nread) {
		uint8_t token_type;
		uint16_t token_len;

		token_type = buf_get8(conn);
		switch (token_type) {
		case TOKEN_COLMETADATA:
			process_colmetadata(conn);
			conn->stage = TDS_BUSY;
			break;
		case TOKEN_ENVCHANGE:
			token_len = buf_get16_le(conn);
			handle_envchange(conn, token_len);
			break;
		case TOKEN_ERROR:
			token_len = buf_get16_le(conn);
			handle_message(conn, TOKEN_ERROR, token_len);
			break;
		case TOKEN_INFO:
			token_len = buf_get16_le(conn);
			handle_message(conn, TOKEN_INFO, token_len);
			break;
		case TOKEN_LOGINACK:
			token_len = buf_get16_le(conn);
			handle_loginack(conn, token_len);
			break;
		case TOKEN_DONE:
		case TOKEN_DONEINPROC:
		case TOKEN_DONEPROC:
			handle_done(conn);
			break;
		case TOKEN_RETURNSTATUS:
			ret = buf_get32_le(conn);
			if (ret != 0) {
				tds_debug(0, "RPC returned %d\n", ret);
			}
			break;
		case TOKEN_ROW:
			handle_row(conn);
			break;
		default:
			tds_debug(0, "unknown type %d\n", token_type);
			break;
		}
	}
}

void
tds_query(struct connection *conn, const char *sql)
{
	uv_write_t *write_req = malloc(sizeof(uv_write_t) + sizeof(uv_buf_t));
	uv_buf_t *pkt = (uv_buf_t *)(write_req + 1);
	unsigned char unicode_buf[1024];
	size_t sql_len;

	/* Before issuing a query verify if this connection is connected. If not
	 * we should connect to the DB first */
	if (conn->stage == TDS_DISCONNECTED || conn->need_connect) {
		/* Save our query first */
		free(conn->sql);
		conn->sql = strdup(sql);
		if (conn->stage != TDS_DISCONNECTED) {
			/* Disconnect first */
			tds_disconnect(conn, 1);
		} else {
			tds_connect(conn);
		}
		return;
	}

	/* No query can be made since our stage is not idle */
	if (conn->stage != TDS_IDLE) {
		return;
	}

	if (conn->need_use && conn->in_use != 1) {
		/* Do use */
		free(conn->sql);
		conn->sql = strdup(sql);
		tds_use_db(conn, conn->database);
	}

	conn->in_use = 0;
	/* Indicate that the connection is now busy */
	conn->stage = TDS_BUSY;

	sql_len = strlen(sql) * 2;
	buf_tds_init(pkt, sql_len, TDS_SQL_BATCH, TDS_EOM);

	buf_addraw(pkt, str_to_ucs2(sql, unicode_buf,
	    sizeof(unicode_buf)), sql_len);

	/* Write header */
	buf_set_hdr(pkt);
	dump_hex(1, pkt->base, pkt->len);

	uv_write(write_req, conn->tcp_handle, pkt, 1, after_write);
}

static void
save_sp(struct connection *conn, const char *proc, struct db_param *params,
    size_t nparams)
{
	int i;

	/* First free existing sp data */
	free(conn->procname);
	for (i = 0; i < conn->n_params; i++) {
		free(conn->params[i].name);
		free(conn->params[i].value);
	}
	free(conn->params);

	conn->procname = strdup(proc);
	conn->n_params = nparams;
	conn->params = calloc(nparams, sizeof(struct db_param));

	for (i = 0; i < conn->n_params; i++) {
		conn->params[i].name = strdup(params[i].name);
		conn->params[i].status = params[i].status;
		conn->params[i].type = params[i].type;
		conn->params[i].maxlen = params[i].maxlen;
		conn->params[i].datalen = params[i].datalen;
		if (params[i].datalen != 0) {
			if (params[i].type == INT4_TYPE) {
				conn->params[i].datalen = 4;
			}
			if (conn->params[i].datalen <= 0) {
				tds_debug(0, "parameter has negative length\n");
			} else {
				conn->params[i].value = malloc(conn->params[i].datalen);
				memcpy(conn->params[i].value, params[i].value,
				    conn->params[i].datalen);
			}
		}
	}
}


void
tds_exec_sp(struct connection *conn, const char *proc, struct db_param *params,
    size_t nparams)
{
	uv_write_t *write_req = malloc(sizeof(uv_write_t) + sizeof(uv_buf_t));
	uv_buf_t *pkt = (uv_buf_t *)(write_req + 1);
	size_t procname_len;
	unsigned char unicode_buf[1024];
	size_t i;

	/* Save proc and params */
	save_sp(conn, proc, params, nparams);

	/* Before executing a stored procedure  verify that this connection is
	 * connected. If not we should connect to the DB first */
	if (conn->stage == TDS_DISCONNECTED || conn->need_connect) {

		if (conn->stage != TDS_DISCONNECTED) {
			/* Disconnect first */
			tds_disconnect(conn, 1);
		} else {
			tds_connect(conn);
		}
		return;
	}

	/* No query can be made since our stage is not idle */
	if (conn->stage != TDS_IDLE) {
		return;
	}

	if (conn->need_use && conn->in_use != 1) {
		/* Do use */
		tds_use_db(conn, conn->database);
	}

	conn->in_use = 0;
	/* Indicate that the connection is now busy */
	conn->stage = TDS_BUSY;

	procname_len = strlen(proc);

	buf_tds_init(pkt, 1024, TDS_RPC, TDS_EOM);
	buf_add16_le(pkt, procname_len);
	buf_addraw(pkt, str_to_ucs2(proc, unicode_buf,
	    sizeof(unicode_buf)), strlen(proc) * 2);

	/* Options */
	buf_add16_le(pkt, 0);
	for (i = 0; i < nparams; i++) {
		size_t len;

		len = strlen(params[i].name);

		buf_add8(pkt, len);
		buf_addraw(pkt, str_to_ucs2(params[i].name, unicode_buf,
	    sizeof(unicode_buf)), len * 2);
		buf_add8(pkt, params[i].status); /* Status: Output parameter */

		/* Type info */
		/* String param specific */
		buf_add8(pkt, 0xe7); /* datatype, 0xe7 = VARCHAR */
		len = strlen((char *)params[i].value);
		if (len >= 4000)
			buf_add16_le(pkt, (1 << 16) - 1); /* MAX */
		else
			buf_add16_le(pkt, len * 2);

		buf_addraw(pkt, conn->env.collation, sizeof(conn->env.collation));

		/* Parameter info */
		buf_add16_le(pkt, len * 2);
		buf_addraw(pkt, str_to_ucs2((char *)params[i].value, unicode_buf,
	    sizeof(unicode_buf)), len * 2);
	}
	buf_set_hdr(pkt);
	dump_hex(0, pkt->base, pkt->len);
	uv_write(write_req, conn->tcp_handle, pkt, 1, after_write);
}
