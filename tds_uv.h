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

#ifndef __TDS_UV_H__
#define __TDS_UV_H__

#include <uv.h>

struct tds_env {
	unsigned char collation[5];
	char *database;
	char *language;
	char *charset;
	int packet_size;
};

#define TDS_COLUMN_MAX_LEN 256

struct tds_column {
	char name[TDS_COLUMN_MAX_LEN];
	int type;
	int len;
};

struct tds_result {
	int ncols;
	struct tds_column *cols;
};

struct connection {
	uv_loop_t *loop;
	char ip_addr[16];

	/* connection properties */
	char server[256];
	unsigned short port;
	char instance[16];
	char user[256];
	char password[256];
	char database[256];

	int need_connect;
	int need_use;

	int stage;

	uv_stream_t *tcp_handle;

	unsigned char *buffer;
	unsigned short b_offset;
	struct tds_env env;

	void (*on_ready)(struct connection *);

	/* Stores the current result, if any. */
	struct tds_result result;
};

struct db_param {
	char *name;
	unsigned char status;
	int type;
	unsigned short maxlen;
	unsigned short datalen;
	unsigned char *value;
};

/* Connection stages */
#define TDS_DISCONNECTED 0
#define TDS_RESOLVING    1
#define TDS_CONNECTING   2
#define TDS_CONNECTED    3
#define TDS_LOGGING_IN   4
#define TDS_LOGGED_IN    5
#define TDS_IDLE         6
#define TDS_BUSY         7

/* A generic UV eventful allocation function */
void gen_on_alloc(uv_handle_t* client, size_t suggested_size, uv_buf_t* buf);
void after_write(uv_write_t *req, int status);

void tds_connect_sa(struct connection *conn, const struct sockaddr *addr);
int tds_connect(struct connection *conn);

struct connection *tds_connection_alloc(void);
void tds_connection_free(struct connection *con);

void tds_set_sql_server(struct connection *conn, const char *dbserver);
void tds_set_password(struct connection *conn, const char *password);
void tds_set_username(struct connection *conn, const char *username);
void tds_set_dbname(struct connection *conn, const char *dbname);
void tds_set_port(struct connection *conn, unsigned short port);

#endif /* __TDS_UV_H__ */

