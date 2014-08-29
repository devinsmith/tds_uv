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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* test for tds_uv */
#include "tds_log.h"
#include "tds_tokens.h"
#include "tds_uv.h"

static void
on_done(struct connection *conn, int row_count)
{
	tds_query(conn, "SELECT TOP 10 * FROM coders");
}

static void
server_connected(struct connection *conn)
{
	tds_debug(0, "Connected (callback)\n");

	conn->on_done = on_done;
	tds_query(conn, "USE [test]");
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

	conn.loop = uv_default_loop();

	if (tds_connect(&conn, server_connected) != 0) {
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);

	uv_run(conn.loop, UV_RUN_DEFAULT);
	free(conn.buffer);
	return 0;
}
