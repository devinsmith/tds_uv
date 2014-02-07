#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

uv_loop_t *loop;

struct connection {
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
on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
	char addr[17];
	uv_connect_t *connect_req;
	uv_tcp_t *socket;

	if (status < 0) {
		fprintf(stderr, "getaddrinfo callback error: %s\n", uv_strerror(status));
		return;
	}

	addr[16] = '\0';
	uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
	fprintf(stderr, "%s\n", addr);

	connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
	socket = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, socket);

	connect_req->data = (void*) socket;
	uv_tcp_connect(connect_req, socket, res->ai_addr,
	    on_connect);

	uv_freeaddrinfo(res);
	free(resolver);
}

int
resolve_connect(struct connection *conn)
{
	int r;
	uv_getaddrinfo_t *resolver;

	resolver = (uv_getaddrinfo_t *)malloc(sizeof(uv_getaddrinfo_t));
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