#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "utils.h"

uv_loop_t *loop;

struct connection {
	char ip_addr[16];
	char *server;
	char *port;
	char *instance;
};


static void
on_connect(uv_connect_t *req, int status)
{
	if (status == -1) {
		fprintf(stderr, "connect failed error %s\n", uv_strerror(status));
		free(req);
		return;
	}

	free(req);
}

static void
detect_on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags)
{
	if (nread < 0) {

		fprintf(stderr, "detect port read error\n");
		/* Error or EOF */
		if (buf->base) {
			free(buf->base);
		}

		uv_close((uv_handle_t*) handle, NULL);
		return;
	}

	if (nread == 0) {
		fprintf(stderr, "nothing read\n");
		/* Everything OK, but nothing read. */
		free(buf->base);
		uv_udp_recv_stop(handle);
		return;
	}

	fprintf(stderr, "%d bytes read\n", (int)nread);
	dump_hex(buf->base, nread);
	free(buf->base);
	uv_udp_recv_stop(handle);
}

void
on_alloc(uv_handle_t* client, size_t suggested_size, uv_buf_t* buf)
{
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

void on_send(uv_udp_send_t *req, int status)
{
	int r;

	if (status != 0) {
		fprintf(stderr, "send failed\n");
		return;
	}

	r = uv_udp_recv_start(req->handle, on_alloc, detect_on_read);
	if (r != 0) {
		fprintf(stderr, "couldn't recv handle\n");
	}
}

static int
detect_port(struct connection *conn)
{
	uv_udp_t *send_socket;
	uv_udp_send_t *send_req;
	struct sockaddr_in send_addr;
	unsigned char msg[128];
	uv_buf_t buffer;
	int l;

	/* Setup our sending UDP datagram */
	send_socket = malloc(sizeof(uv_udp_t));
	//send_socket->data = conn;

	uv_udp_init(loop, send_socket);
	fprintf(stderr, "Sending to %s:1434\n", conn->ip_addr);

	memset(msg, 0, sizeof(msg));
	msg[0] = 4;
	l = snprintf((char *)msg + 1, sizeof(msg) - 1, "%s", conn->instance);

	buffer.len = 1 + l;
	buffer.base = (char *)msg;

	send_req = malloc(sizeof(uv_udp_send_t));
	send_req->data = conn;

	uv_ip4_addr(conn->ip_addr, 1434, &send_addr);
	uv_udp_send(send_req, send_socket, &buffer, 1,
	    (const struct sockaddr *)&send_addr, on_send);

	return 0;
}


static void
on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
	uv_connect_t *connect_req;
	uv_tcp_t *socket;
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
	if (conn->port) {
		connect_req = malloc(sizeof(uv_connect_t));
		socket = malloc(sizeof(uv_tcp_t));
		uv_tcp_init(loop, socket);

		connect_req->data = (void*) socket;
		uv_tcp_connect(connect_req, socket, res->ai_addr,
		    on_connect);
	} else {
		fprintf(stderr, "no port! Need to detect.\n");
		detect_port(conn);
	}

	uv_freeaddrinfo(res);
	free(resolver);
}

int
resolve_connect(struct connection *conn)
{
	int r;
	uv_getaddrinfo_t *resolver;

	/* Allocate a new resolver, will be freed in "on_resolved" */
	resolver = malloc(sizeof(uv_getaddrinfo_t));
	resolver->data = conn;
	r = uv_getaddrinfo(loop, resolver, on_resolved, conn->server, conn->port,
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
			conn.port = *++argv, --argc;
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
