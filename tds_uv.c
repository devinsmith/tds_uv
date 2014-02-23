#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "sqlrp.h"
#include "tds_buf.h"
#include "tds_log.h"
#include "tds_uv.h"
#include "utils.h"

uv_loop_t *loop;

/* The different stages of our TDS connection */
#define TDS_DISCONNECTED 0
#define TDS_RESOLVING    1
#define TDS_CONNECTING   2
#define TDS_CONNECTED    3
#define TDS_LOGGING_IN   4
#define TDS_LOGGED_IN    5
#define TDS_IDLE         6

static void after_write(uv_write_t *req, int status);

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
	buf_raw_init(pkt, 256);
	buf_add8(pkt, 0x10); /* Login packet = 0x10  */
	buf_add8(pkt, 0x01); /* "Normal" status message */
	buf_add16(pkt, 0xBAAD); /* length in big endian (filled later) */
	buf_add16(pkt, 0); /* SPID */
	buf_add8(pkt, 1); /* Packet Id */
	buf_add8(pkt, 0); /* Window Id (always 0) */
	/* Here we end the standard TDS packet header */

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
	buf_add32_le(pkt, 0); /* Time zone (TODO) */
	buf_add32_le(pkt, 0); /* LCID (TODO) */

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

	tds_debug(0, "%d\n", len_pass);

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

	tds_debug(0, "pkt len: %d\n", (int)pkt->len);
	dump_hex(pkt->base, pkt->len);

	uv_write(write_req, tcp, pkt, 1, after_write);
}

static void
tds_on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
	struct connection *conn = tcp->data;
	uint16_t pkt_len;

	if (nread < 0) {
		tds_debug(0, "tds_on_read port read error: %d\n", nread);
		/* Error or EOF */
		conn->b_offset = 0;

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
	if (buf->base[0] != 4) {
		tds_debug(0, "first byte is not 4: %d\n", buf->base[0]);
		conn->b_offset = 0;
		uv_close((uv_handle_t*) tcp, NULL);
		return;
	}

	pkt_len = (unsigned char)buf->base[2] << 8;
	pkt_len += (unsigned char)buf->base[3];

	tds_debug(0, "%d bytes read (pkt: %d)\n", (int)nread, pkt_len);

	conn->b_offset += nread;
	tds_debug(0, "Stage: %d\n", conn->stage);

	/* XXX: Only process if we have a complete packet */

	switch (conn->stage) {
	case TDS_CONNECTED:
		/* XXX: Process prelogin packet */
		send_login(tcp, conn);
		break;
	default:
		dump_hex(buf->base, nread);
		break;
	}
	if (nread == pkt_len)
		conn->b_offset = 0;
}

static void
after_write(uv_write_t *req, int status)
{
	uv_buf_t *resbuf = (uv_buf_t *)(req + 1);

	free(resbuf->base);
	free(req);
}

static void
send_prelogin(uv_stream_t *stream, struct connection *conn)
{
	uv_write_t *write_req = malloc(sizeof(uv_write_t) + sizeof(uv_buf_t));
	uv_buf_t *pkt = (uv_buf_t *)(write_req + 1);
	size_t token_offset;
	size_t data_offset;
	unsigned char *size_ptr;

	/* Packet header is always 8 bytes */
	buf_raw_init(pkt, 128);
	buf_add8(pkt, 0x12); /* Prelogin */
	buf_add8(pkt, 0x01); /* "Normal" status message */
	buf_add16(pkt, 0xBAAD); /* length in big endian (filled later) */
	buf_add16(pkt, 0); /* SPID */
	buf_add8(pkt, 0); /* Packet Id */
	buf_add8(pkt, 0); /* Window Id (always 0) */
	/* Here we end the standard TDS packet header */

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
	buf_add8(pkt, 9);
	buf_add8(pkt, 0);
	buf_add16(pkt, 0);
	/* US_SUBBUILD */
	buf_add16(pkt, 0);

	/* TOKEN 1 (ENCRYPTION) */
	buf_add8(pkt, 2); /* Encryption not supported */

	/* TOKEN 2 (INSTOPT) */
	buf_addstring(pkt, conn->instance);
	buf_add8(pkt, 0); /* terminating byte */

	/* TOKEN 3 (THREADID) */
	buf_add32(pkt, 0); /* getpid? */

	/* Write header */
	buf_set_hdr(pkt);

	tds_debug(0, "pkt len: %d\n", (int)pkt->len);
	dump_hex(pkt->base, pkt->len);

	uv_write(write_req, stream, pkt, 1, after_write);
}

static void
on_connect(uv_connect_t *req, int status)
{
	struct connection *conn = req->data;
	uv_stream_t *stream = req->handle;

	if (status == -1) {
		tds_debug(0, "connect failed error %s\n", uv_strerror(status));
		free(req);
		return;
	}

	tds_debug(0, "Connected!\n");
	conn->stage = TDS_CONNECTED;
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
tds_connect(struct connection *conn, const struct sockaddr *addr)
{
	uv_connect_t *connect_req;
	uv_tcp_t *socket;

	connect_req = malloc(sizeof(uv_connect_t));
	socket = malloc(sizeof(uv_tcp_t));

	uv_tcp_init(loop, socket);
	conn->stage = TDS_CONNECTING;
	connect_req->data = conn;
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
	tds_debug(0, "%s\n", conn->ip_addr);

	/* At this point we should have an IP address for our hostname, but
	 * we may not have a port. */
	if (conn->port > 0) {
		tds_connect(conn, (struct sockaddr *)res->ai_addr);
	} else {
		tds_debug(0, "no port! Need to detect.\n");
		sqlrp_detect_port(loop, conn);
	}

cleanup:
	uv_freeaddrinfo(res);
	free(resolver);
}

int
resolve_connect(struct connection *conn)
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
	r = uv_getaddrinfo(loop, resolver, on_resolved, conn->server, pport,
	    NULL);

	if (r) {
		free(resolver);
		tds_debug(0, "getaddrinfo call error %s\n", uv_strerror(r));
		return 1;
	}

	return r;
}

static void
args_required(char *arg)
{
	fprintf(stderr, "option '%s' expects a parameter.\n", arg);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct connection conn;
	char *p;

	memset(&conn, 0, sizeof(struct connection));
	conn.buffer = malloc(65535);

	/* Parse arguments */
	while (--argc) {
		p = *++argv;

		if (!strcmp(p, "-s")) {
			if (!argv[1]) {
				args_required(p);
			}
			conn.server = *++argv, --argc;
		} else if (!strcmp(p, "-P")) {
			if (!argv[1]) {
				args_required(p);
			}
			conn.port = atoi(*++argv), --argc;
		} else if (!strcmp(p, "-p")) {
			if (!argv[1]) {
				args_required(p);
			}
			conn.password = *++argv, --argc;
		} else if (!strcmp(p, "-u")) {
			if (!argv[1]) {
				args_required(p);
			}
			conn.user = *++argv, --argc;
		}
	}

	if (!conn.server) {
		fprintf(stderr, "Please specify a hostname\n");
		return 1;
	}

	if (!conn.user) {
		fprintf(stderr, "A username is required.\n");
		return 1;
	}

	if (!conn.password) {
		fprintf(stderr, "A password is required.\n");
		return 1;
	}

	if ((p = strchr(conn.server, '\\'))) {
		fprintf(stderr, "detecting instance\n");
		conn.instance = p + 1;
		*p = '\0';
		fprintf(stderr, "instance: %s\n", conn.instance);
	}

	tds_debug_init();
	tds_debug_set_log_level(0);

	loop = uv_default_loop();

	if (resolve_connect(&conn) != 0) {
		return 1;
	}

	uv_run(loop, UV_RUN_DEFAULT);
	free(conn.buffer);
	return 0;
}

