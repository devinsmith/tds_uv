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

/* Implementation for Microsoft SQL Server Resolution Protocol. */
/* See [MC-SQLR].pdf for specification */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlrp.h"
#include "utils.h"

/* SQL Server Resolution Protocol communicates over UDP port 1434 */
#define SQLRP_PORT 1434

/* Message types ([MC-SQLR].pdf section 2.2) */
#define CLNT_UCAST_INST 0x04

#ifdef WIN32
#define strcasecmp _stricmp
#endif

static void
sqlrp_on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags)
{
	char *p;
	struct connection *conn = handle->data;
	int port_found = 0;
	int instance_found = 0;
	long l = 0;

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
	buf->base[nread - 1] = '\0';
	dump_hex(buf->base, nread);
	/* TODO: Handle */
	if (buf->base[0] != 5) {
		fprintf(stderr, "invalid packet received\n");
		goto done;
	}
	fprintf(stderr, "%s\n", conn->instance);

	p = buf->base + 3; /* Skip packet type + length */
	while (*p) {
		char *name, *value;

		name = p;
		p = strchr(p, ';');
		if (!p)
			break;

		*p++ = '\0';

		value = name;
		if (*name) {
			value = p;
			p = strchr(p, ';');
			if (!p)
				break;
			*p++ = '\0';
		}

		if (strcasecmp(name, "InstanceName") == 0) {
			if (strcasecmp(value, conn->instance))
				break;
			instance_found = 1;
		} else if (strcasecmp(name, "tcp") == 0) {

			l = strtol(value, &p, 10);
			if (l > 0 && l <= 0xffff && *p == 0)
				port_found = 1;
		}
	}
	if (instance_found && port_found) {
		struct sockaddr_in addr;
		conn->port = l;
		fprintf(stderr, "Port = %d\n", conn->port);
		uv_ip4_addr(conn->ip_addr, conn->port, &addr);
		tds_connect(conn, (struct sockaddr *)&addr);
	}

done:
	free(buf->base);
	uv_udp_recv_stop(handle);
	free(handle);
}

static void
sqlrp_on_send(uv_udp_send_t *req, int status)
{
	int r;
	uv_buf_t *reqbuf = (uv_buf_t *)(req + 1);

	if (status != 0) {
		fprintf(stderr, "send failed\n");
		return;
	}

	r = uv_udp_recv_start(req->handle, gen_on_alloc, sqlrp_on_read);
	if (r != 0) {
		fprintf(stderr, "couldn't recv handle\n");
	}

	free(reqbuf->base);
	free(req);
}

int
sqlrp_detect_port(uv_loop_t *loop, struct connection *conn)
{
	uv_udp_t *send_socket;
	uv_udp_send_t *send_req;
	struct sockaddr_in send_addr;
	char *msg;
	uv_buf_t *buffer;
	int l;

	/* Setup our sending UDP datagram */
	send_socket = malloc(sizeof(uv_udp_t));
	send_socket->data = conn;

	uv_udp_init(loop, send_socket);
	fprintf(stderr, "Sending to %s:%d\n", conn->ip_addr, SQLRP_PORT);

	msg = calloc(128, 1);
	msg[0] = CLNT_UCAST_INST;
	/* The instance name must be no greater than 32 characters not including
	 * the NULL terminator. */
	l = snprintf(msg + 1, 32, "%s", conn->instance);

	/* Piggy back our buffer onto send_req to save a malloc */
	send_req = malloc(sizeof(uv_udp_send_t) + sizeof(uv_buf_t));
	buffer = (uv_buf_t *)(send_req + 1);
	buffer->len = 1 + l;
	buffer->base = msg;

	uv_ip4_addr(conn->ip_addr, SQLRP_PORT, &send_addr);
	uv_udp_send(send_req, send_socket, buffer, 1,
	    (const struct sockaddr *)&send_addr, sqlrp_on_send);

	return 0;
}

