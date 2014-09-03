#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "constants.h"
#include "sqlrp.h"
#include "tds_buf.h"
#include "tds_log.h"
#include "tds_prelogin.h"
#include "tds_tokens.h"
#include "tds_uv.h"
#include "utils.h"

enum tds_login7_optionflag1_values {
	TDS_DUMPLOAD_OFF = 0x10,
	TDS_USE_DB_NOTIFY = 0x20,
	TDS_INIT_DB_FATAL = 0x40,
	TDS_SET_LANG_ON = 0x80
};

enum tds_login7_optionflag2_values {
	TDS_INIT_LANG_REQUIRED = 0x01,
	TDS_ODBC_ON = 0x02
};

static void send_login(uv_stream_t *tcp, struct connection *conn);

static void
send_login(uv_stream_t *tcp, struct connection *conn)
{
	uv_write_t *write_req = malloc(sizeof(uv_write_t) + sizeof(uv_buf_t));
	uv_buf_t *pkt = (uv_buf_t *)(write_req + 1);
	size_t login7_len_offset;
	unsigned char *size_ptr;
	unsigned int login_len;
	unsigned char unicode_buf[1024];
	size_t len_user, len_pass;
	size_t len_server;
	size_t cur_pos;

	conn->stage = TDS_LOGGING_IN;
	len_user = strlen(conn->user);
	len_pass = strlen(conn->password);
	len_server = strlen(conn->server);
	if (conn->instance)
		len_server += strlen(conn->instance) + 1;

	/* Packet header is always 8 bytes */
	buf_tds_init(pkt, 256, TDS_LOGIN, TDS_EOM);

	/* The first part of the login 7 packet is the length. */
	login7_len_offset = pkt->len;
	buf_add32_le(pkt, 0); /* Length to be filled in later */
	buf_add32_le(pkt, 0x71000001); /* Tell SQL Server we at least support 2000 */
	buf_add32_le(pkt, 4096); /* Packet size */
	buf_add32_le(pkt, 7); /* Client version. Is this a magic number? */
	buf_add32_le(pkt, 0); /* Pid */
	buf_add32_le(pkt, 0); /* connection id */

	/* OptionFlags1 (see tds_login7_optionflag1_values) */
	buf_add8(pkt, TDS_DUMPLOAD_OFF |
	    TDS_USE_DB_NOTIFY | TDS_INIT_DB_FATAL | TDS_SET_LANG_ON);

	/* OptionFlags2 (see tds_login7_optionflag2_values) */
	buf_add8(pkt, TDS_INIT_LANG_REQUIRED | TDS_ODBC_ON);

	buf_add8(pkt, 0); /* SQL type */
	buf_add8(pkt, 8); /* option3 */
	buf_add32_le(pkt, 0xffffff88); /* Time zone (TODO) */
	buf_add32_le(pkt, 0x436); /* LCID (TODO) */

	/* Now the variable part of the packet data. */
	cur_pos = 86;
	buf_add16_le(pkt, cur_pos); /* offset filled in later */
	buf_add16_le(pkt, strlen("hostname")); /* hardcoding some stuff for now */
	cur_pos += strlen("hostname") * 2;

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, len_user);
	cur_pos += len_user * 2;

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, len_pass);
	cur_pos += len_pass * 2;

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, strlen("Microsoft"));
	cur_pos += strlen("Microsoft") * 2;

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, len_server);
	cur_pos += len_server * 2;

	/* ibUnused & cbUnused */
	buf_add16_le(pkt, 0); /* This should be set to 0 */
	buf_add16_le(pkt, 0);

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, strlen("DB-Library"));
	cur_pos += strlen("DB-Library") * 2;

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, strlen("us_english"));
	cur_pos += strlen("us_english") * 2;

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, 0); /* database length */

	buf_addzero(pkt, 6); /* MAC Addr */

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, 0); /* auth length */

	buf_add16_le(pkt, cur_pos);
	buf_add16_le(pkt, 0); /* db length */

	buf_addraw(pkt, str_to_ucs2("hostname", unicode_buf,
	    sizeof(unicode_buf)), 16);

	buf_addraw(pkt, str_to_ucs2(conn->user, unicode_buf,
	    sizeof(unicode_buf)), len_user * 2);

	buf_addraw(pkt, tds7_crypt_pass(str_to_ucs2(conn->password, unicode_buf,
	    sizeof(unicode_buf)), len_pass * 2, unicode_buf), len_pass * 2);

	buf_addraw(pkt, str_to_ucs2("Microsoft", unicode_buf,
	    sizeof(unicode_buf)), strlen("Microsoft") * 2);

	buf_addraw(pkt, str_to_ucs2(conn->server, unicode_buf,
	    sizeof(unicode_buf)), strlen(conn->server) * 2);

	if (conn->instance) {
		buf_addraw(pkt, str_to_ucs2("\\", unicode_buf,
		    sizeof(unicode_buf)), 2);

		buf_addraw(pkt, str_to_ucs2(conn->instance, unicode_buf,
		    sizeof(unicode_buf)), strlen(conn->instance) * 2);
	}

	buf_addraw(pkt, str_to_ucs2("DB-Library", unicode_buf,
	    sizeof(unicode_buf)), strlen("DB-Library") * 2);

	buf_addraw(pkt, str_to_ucs2("us_english", unicode_buf,
	    sizeof(unicode_buf)), strlen("us_english") * 2);

	size_ptr = (unsigned char *)pkt->base + login7_len_offset;
	login_len = pkt->len - login7_len_offset;
	*size_ptr++ = (login_len & 0xff);
	*size_ptr++ = (login_len & 0xff00) >> 8;
	*size_ptr++ = (login_len & 0xff0000) >> 16;
	*size_ptr++ = (login_len & 0xff000000) >> 24;

	/* Write header */
	buf_set_hdr(pkt);

	tds_debug(0, "> LOGIN packet (%d bytes)\n", (int)pkt->len);
	dump_hex(1, pkt->base, pkt->len);

	uv_write(write_req, tcp, pkt, 1, after_write);
}

/* For every message read off the wire we'll start here */
static void
tds_on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
	struct connection *conn = tcp->data;
	uint16_t pkt_len;

	tds_debug(1, "+PACKET (bytes: %d)\n", nread);
	if (nread < 0) {
		if (nread != UV__EOF) {
			tds_debug(0, "tds_on_read port read error: %d\n", nread);
		}
		/* Error or EOF */
		conn->b_offset = 0;

		tds_debug(0, "Closing connection\n");
		uv_close((uv_handle_t*) tcp, NULL);
		return;
	}

	if (nread == 0) {
		tds_debug(0, "tds_on_read nothing read\n");
		/* Everything OK, but nothing read. */
		conn->b_offset = 0;
		return;
	}

	/* Verify that the response from the server is 4, if not kill the
	 * connection. */
	if (conn->b_offset == 0 && buf->base[0] != 0x04) {
		tds_debug(0, "first byte is not 4: %d\n", buf->base[0]);
		conn->b_offset = 0;
		uv_close((uv_handle_t*) tcp, NULL);
		return;
	}

	conn->b_offset += nread;
	/* Need first 4 bytes to get packet length */
	if (conn->b_offset < 4)
		return;

	pkt_len = conn->buffer[2] << 8;
	pkt_len += conn->buffer[3];

	/* Don't process until we get a full packet */
	if (conn->b_offset < pkt_len) {
		tds_debug(0, "%d bytes read (pkt: %d)\n", (int)nread, pkt_len);
		return;
	}

	/* Full packet, reset index */
	conn->b_offset = 0;


	if (conn->stage == TDS_CONNECTED) {
		tds_debug(0, "+PRELOGIN response (TODO)\n"); 
		/* XXX: Process prelogin packet */
		send_login(tcp, conn);
	} else {
		tds_debug(0, "Stage: %d\n", conn->stage);
		handle_tokens(conn, nread);
	}
	conn->b_offset = 0;


	if (conn->stage == TDS_IDLE && conn->need_use) {
		tds_use_db(conn, conn->database);
	}

	if (conn->stage == TDS_IDLE) {
		if (conn->sql)
			tds_query(conn, conn->sql);
		if (conn->on_ready)
			conn->on_ready(conn);
	}
}

void
after_write(uv_write_t *req, int status)
{
	uv_buf_t *resbuf = (uv_buf_t *)(req + 1);

	free(resbuf->base);
	free(req);
}

static void
on_connect(uv_connect_t *req, int status)
{
	struct connection *conn = req->data;
	uv_stream_t *stream = req->handle;

	conn->tcp_handle = stream;

	if (status == -1) {
		tds_debug(0, "connect failed error %s\n", uv_strerror(status));
		free(req);
		return;
	}

	tds_debug(0, "> Connected!\n");
	conn->stage = TDS_CONNECTED;
	conn->need_connect = 0;
	send_prelogin(stream, conn);

	stream->data = conn;
	uv_read_start(stream, gen_on_alloc, tds_on_read);

	free(req);
}

void
gen_on_alloc(uv_handle_t* client, size_t suggested_size, uv_buf_t* buf)
{
	struct connection *conn = client->data;
	buf->base = (char *)conn->buffer + conn->b_offset;
	buf->len = suggested_size - conn->b_offset;
}

void
tds_connect_sa(struct connection *conn, const struct sockaddr *addr)
{
	uv_connect_t *connect_req;
	uv_tcp_t *socket;

	connect_req = malloc(sizeof(uv_connect_t));
	socket = malloc(sizeof(uv_tcp_t));

	uv_tcp_init(conn->loop, socket);
	conn->stage = TDS_CONNECTING;
	connect_req->data = conn;
	tds_debug(0, "> Connecting...\n");
	uv_tcp_connect(connect_req, socket, addr, on_connect);
}

static void
on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
	struct connection *conn = resolver->data;

	if (status < 0) {
		tds_debug(0, "Failed to resolve name (%d): %s\n", status,
		    uv_strerror(status));
		goto cleanup;
	}

	uv_ip4_name((struct sockaddr_in *)res->ai_addr, conn->ip_addr,
	    sizeof(conn->ip_addr));

	/* At this point we should have an IP address (stored in conn->ip_addr) for
	 * our hostname, but we may not have a port. */
	if (conn->port > 0) {
		tds_connect_sa(conn, (struct sockaddr *)res->ai_addr);
	} else {
		sqlrp_detect_port(conn->loop, conn);
	}

cleanup:
	uv_freeaddrinfo(res);
	free(resolver);
}

int
tds_connect(struct connection *conn)
{
	int r;
	uv_getaddrinfo_t *resolver;
	char port[sizeof("65535")];
	char *pport = NULL;

	/* Allocate a new resolver, will be freed in "on_resolved" */
	resolver = malloc(sizeof(uv_getaddrinfo_t));
	conn->stage = TDS_RESOLVING;
	resolver->data = conn;
	if (conn->port > 0) {
		snprintf(port, sizeof(port), "%d", conn->port);
		pport = port;
	}
	r = uv_getaddrinfo(conn->loop, resolver, on_resolved, conn->server, pport,
	    NULL);

	if (r) {
		free(resolver);
		tds_debug(0, "getaddrinfo call error %s\n", uv_strerror(r));
		return 1;
	}

	return r;
}

struct connection *
tds_connection_alloc(void)
{
	struct connection *ret;

	ret = calloc(1, sizeof(struct connection));
	ret->buffer = malloc(65535);
	ret->need_connect = 1;
	ret->need_use = 1;

	return ret;
}

void
tds_connection_free(struct connection *con)
{
	free(con->buffer);
	free(con);
}

void
tds_use_db(struct connection *conn, const char *db)
{
	char use_stmt[300];
	conn->in_use = 1;
	snprintf(use_stmt, sizeof(use_stmt), "USE [%s]", conn->database);
	tds_query(conn, use_stmt);
}

void
tds_set_password(struct connection *conn, const char *password)
{
	if (strcmp(conn->password, password) != 0) {
		conn->need_connect = 1;
		conn->need_use = 1;
		snprintf(conn->password, sizeof(conn->password), "%s", password);
	}
}

void
tds_set_username(struct connection *conn, const char *username)
{
	if (strcmp(conn->user, username) != 0) {
		conn->need_connect = 1;
		conn->need_use = 1;
		snprintf(conn->user, sizeof(conn->user), "%s", username);
	}
}

void
tds_set_sql_server(struct connection *conn, const char *dbserver)
{
	char tmp[256];
	char *p;

	/* Extract instance */
	snprintf(tmp, sizeof(tmp), dbserver);
	if ((p = strchr(tmp, '\\')) != NULL) {
		*p = '\0';

		if (strcmp(conn->instance, p + 1) != 0) {
			conn->need_connect = 1;
			conn->need_use = 1;
			snprintf(conn->instance, sizeof(conn->instance), "%s", p + 1);
		}
	}

	if (strcmp(conn->server, tmp) != 0) {
		conn->need_connect = 1;
		conn->need_use = 1;

		snprintf(conn->server, sizeof(conn->server), "%s", tmp);
	}
}

void
tds_set_dbname(struct connection *conn, const char *dbname)
{
	if (strcmp(conn->database, dbname)) {
		conn->need_use = 1;
		snprintf(conn->database, sizeof(conn->database), "%s", dbname);
	}
}

void
tds_set_port(struct connection *conn, unsigned short port)
{
	if (port != conn->port) {
		conn->port = port;
		conn->need_connect = 1;
		conn->need_use = 1;
	}
}

static void
tds_reconnect(uv_handle_t *handle)
{
	tds_connect((struct connection *)handle->data);
}

int
tds_disconnect(struct connection *conn, int reconnect)
{
	if (reconnect) {
		uv_close((uv_handle_t*) conn->tcp_handle, tds_reconnect);
	} else {
		uv_close((uv_handle_t*) conn->tcp_handle, NULL);
	}
	conn->need_connect= 1;
	conn->need_use = 1;
	conn->stage = TDS_DISCONNECTED;
	return 0;
}
