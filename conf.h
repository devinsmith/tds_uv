/*
 * Copyright (c) 2012 Devin Smith <devin@devinsmith.net>
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

#ifndef __DRS_CONF_H__
#define __DRS_CONF_H__

#include <stdio.h>

union val_type {
	int i;
	char *s;
};

struct opt_table {
	char *name;
	int type;
	union val_type val;
};

struct prog_cfg {
	/* SQL specific */
	char *sql_server;
	int sql_port;
	char *sql_user;
	char *sql_password;
	char *sql_database;
};

#define TYPE_INT	0
#define TYPE_STRING	1

#define SET_STRING(x)	{ .s = (x) }
#define SET_INT(x)	{ .i = (x) }

int parse_conf(FILE *fp, struct opt_table *conf, int num_elements);
void free_conf(struct opt_table *conf, int num_elements);
int read_config(const char *file);

#endif /* __DRS_CONF_H__ */

