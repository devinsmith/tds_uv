#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

uv_loop_t *loop;

static void
on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
	char addr[17];
	if (status < 0) {
		fprintf(stderr, "getaddrinfo callback error\n");
		return;
	}

	addr[16] = '\0';
	uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
	fprintf(stderr, "%s\n", addr);
}

int
main(int argc, char *argv[])
{
	int r;
	uv_getaddrinfo_t resolver;
	char *port = NULL;

	if (argc < 2) {
		fprintf(stderr, "Please specify a hostname\n");
		return 1;
	}

	if (argc > 2) {
		port = argv[2];
	}

	loop = uv_default_loop();

	r = uv_getaddrinfo(loop, &resolver, on_resolved, argv[1], port,
	    NULL);

	if (r) {
		fprintf(stderr, "getaddrinfo call error %s\n", uv_strerror(r));
		return 1;
	}
	return uv_run(loop, UV_RUN_DEFAULT);
}
