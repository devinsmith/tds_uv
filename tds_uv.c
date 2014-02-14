#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "sqlrp.h"
#include "tds_packet.h"
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
#define TDS_READY        6

static void
tds_on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
	if (nread < 0) {
		fprintf(stderr, "tds_on_read port read error\n");
		/* Error or EOF */
		if (buf->base) {
			free(buf->base);
		}

		uv_close((uv_handle_t*) tcp, NULL);
		return;
	}

	if (nread == 0) {
		fprintf(stderr, "tds_on_read nothing read\n");
		/* Everything OK, but nothing read. */
		free(buf->base);
		return;
	}

	fprintf(stderr, "%d bytes read\n", (int)nread);
	dump_hex(buf->base, nread);
	free(buf->base);
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
	struct pkt *p;
	uv_write_t *write_req = malloc(sizeof(write_req) + sizeof(uv_buf_t));
	uv_buf_t *resbuf = (uv_buf_t *)(write_req + 1);
	size_t token_offset;
	size_t data_offset;
	unsigned char *size_ptr;

	/* Packet header is always 8 bytes */
	p = pkt_raw_init(128, FIXED_PACKET);
	pkt_add8(p, 0x12); /* Prelogin */
	pkt_add8(p, 0x01); /* "Normal" status message */
	pkt_add16(p, 0xBAAD); /* length in big endian (filled later) */
	pkt_add16(p, 0); /* SPID */
	pkt_add8(p, 0); /* Packet Id */
	pkt_add8(p, 0); /* Window Id (always 0) */
	/* Here we end the standard TDS packet header */

	/* keep a pointer to the start of tokens */
	token_offset = p->len;

	/* Each token has the following components:
	 * TokenType - 1 byte
	 * TokenDataOffset - 2 bytes (big endian)
	 *  -- TokenDataOffset is calculated dynamically below.
	 * TokenDataLength - 2 bytes (big endian)
	 */

	pkt_add8(p, 0); /* Version */
	pkt_add16(p, 0); /* Start position (filled in below)*/
	pkt_add16(p, 6); /* Length */

	pkt_add8(p, 1); /* Encryption */
	pkt_add16(p, 0);
	pkt_add16(p, 1); /* 1 byte */

	pkt_add8(p, 2); /* Instance option */
	pkt_add16(p, 0); /* starting offset */
	pkt_add16(p, strlen(conn->instance) + 1);

	pkt_add8(p, 3); /* thread id */
	pkt_add16(p, 0);
	pkt_add16(p, 4); /* pid is 4 bytes */

	pkt_add8(p, 0xff); /* End of tokens */
	data_offset = p->len - 8; /* 8 is size of header */

	/* Loop through each token and set the TokenDataOffset
	 * correctly. The token terminator is 0xff. */
	size_ptr = p->data + token_offset;
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
	pkt_add8(p, 9);
	pkt_add8(p, 0);
	pkt_add16(p, 0);
	/* US_SUBBUILD */
	pkt_add16(p, 0);

	/* TOKEN 1 (ENCRYPTION) */
	pkt_add8(p, 2); /* Encryption not supported */

	/* TOKEN 2 (INSTOPT) */
	pkt_addstring(p, conn->instance);
	pkt_add8(p, 0); /* terminating byte */

	/* TOKEN 3 (THREADID) */
	pkt_add32(p, 0); /* getpid? */

	/* Write header */
	p->data[2] = (p->len & 0xff00) >> 8;
	p->data[3] = (p->len & 0xff);

	fprintf(stderr, "pkt len: %d\n", (int)p->len);
	resbuf->base = p->data;
	resbuf->len = p->len;
	dump_hex(resbuf->base, resbuf->len);

	uv_write(write_req, stream, resbuf, 1, after_write);
}

static void
on_connect(uv_connect_t *req, int status)
{
	struct connection *conn = req->data;
	uv_stream_t *stream = req->handle;

	if (status == -1) {
		fprintf(stderr, "connect failed error %s\n", uv_strerror(status));
		free(req);
		return;
	}

	fprintf(stderr, "Connected!\n");
	conn->stage = TDS_CONNECTED;
	send_prelogin(stream, conn);
	uv_read_start(stream, gen_on_alloc, tds_on_read);

	free(req);
}

void
gen_on_alloc(uv_handle_t* client, size_t suggested_size, uv_buf_t* buf)
{
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
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
		fprintf(stderr, "Failed to resolve name (%d): %s\n", status,
		    uv_strerror(status));
		return;
	}

	uv_ip4_name((struct sockaddr_in *)res->ai_addr, conn->ip_addr,
	    sizeof(conn->ip_addr));
	fprintf(stderr, "%s\n", conn->ip_addr);

	/* At this point we should have an IP address for our hostname, but
	 * we may not have a port. */
	if (conn->port > 0) {
		tds_connect(conn, (struct sockaddr *)res->ai_addr);
	} else {
		fprintf(stderr, "no port! Need to detect.\n");
		sqlrp_detect_port(loop, conn);
	}

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
		fprintf(stderr, "getaddrinfo call error %s\n", uv_strerror(r));
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

	memset(&conn, 0, sizeof(struct connection));
	/* Parse arguments */
	while (--argc) {
		char *p = *++argv;

		if (!strcmp(p, "-s")) {
			if (!argv[1]) {
				args_required(p);
			}
			conn.server = *++argv, --argc;
		} else if (!strcmp(p, "-i")) {
			if (!argv[1]) {
				args_required(p);
			}
			conn.instance = *++argv, --argc;
		} else if (!strcmp(p, "-p")) {
			if (!argv[1]) {
				args_required(p);
			}
			conn.port = atoi(*++argv), --argc;
		}
	}

	if (!conn.server) {
		fprintf(stderr, "Please specify a hostname\n");
		return 1;
	}

	loop = uv_default_loop();

	if (resolve_connect(&conn) != 0) {
		return 1;
	}

	return uv_run(loop, UV_RUN_DEFAULT);
}

