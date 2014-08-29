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

#include "conf.h"

extern struct prog_cfg *active_cfg;

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

int
main(int argc, char *argv[])
{
	struct connection *conn;

	/* Creates active_cfg */
	if (read_config("test1.conf") == 0) {
		fprintf(stderr, "This program requires a configuration file.\n");
		exit(1);
	}

	/* Create a single TDS connection */
	conn = tds_connection_alloc();
	tds_set_sql_server(conn, active_cfg->sql_server);
	tds_set_port(conn, active_cfg->sql_port);
	tds_set_username(conn, active_cfg->sql_user);
	tds_set_password(conn, active_cfg->sql_password);
	tds_set_dbname(conn, "test");

	tds_debug_init();
	tds_debug_set_log_level(0);

	conn->loop = uv_default_loop();

	if (tds_connect(conn, server_connected) != 0) {
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);

	uv_run(conn->loop, UV_RUN_DEFAULT);
	tds_connection_free(conn);
	return 0;
}
