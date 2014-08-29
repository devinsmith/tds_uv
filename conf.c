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

#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"

/* Provide a default configuration. This will most likely be overwritten */
struct prog_cfg default_cfg = {
	NULL,
	0,
	NULL,
	NULL,
	NULL,
};

struct prog_cfg *active_cfg;

/*
 ** Returns 1 if the string is blank (i.e. contains
 ** nothing but space characters), 0 if it's not blank.
 */
int blank_str(const char *str)
{
	const char *p = str;

	while (*p != '\0')
	{
		if (*p != ' ')
			return 0;
		p++;
	}

	return 1;
}


/* Reads configuration data from the file located at path.
 */
int parse_conf(FILE *fp, struct opt_table *conf, int num_elements)
{
	char buf[4096];
	uint32_t line = 0;

	/* Read in up to new line or at most 4k. */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p;

		++line;

		p = strchr(buf, '\n');
		if (p == NULL)
		{
			fprintf(stderr, "line %u too long\n", line);
			fclose(fp);
			return -1;
		}

		/* Terminate string at the new line */
		*p = '\0';

		p = buf;
		/* Change tabs to spaces */
		while ((p = strchr(p, '\t')) != NULL)
			*p++ = ' ';

		p = buf;
		/* Change '=' to spaces */
		while ((p = strchr(p, '=')) != NULL)
			*p++ = ' ';

		p = buf;
		if (*p == '#') /* Comments start with '#' */
			continue;

		if (!blank_str(p))
		{
			char *key, *val;
			int i;

			val = strchr(p, ' ');
			while (val && *val == ' ') val++;

			if (val == NULL) continue;

			key = strchr(p, ' ');
			*key = '\0';
			key = p;

			for (i = 0; i < num_elements; i++)
			{
				if (strncmp(key, conf[i].name, strlen(key)) == 0)
				{
					if (conf[i].type == TYPE_INT)
						conf[i].val.i = atoi(val);
					else
					{
						conf[i].val.s = strdup(val);
						conf[i].type = 2; /* Mark for cleanup */
					}
				}
			}
		}
	}
	return 0;
}

void free_conf(struct opt_table *conf, int num_elements)
{
	int i;

	for (i = 0; i < num_elements; i++)
	{
		if (conf[i].type == 2 && conf[i].val.s != NULL)
		{
			free(conf[i].val.s);
			conf[i].val.s = NULL;
			conf[i].type = 1;
		}
	}
}

static char *
null_strdup(const char *in)
{
	if (in)
		return strdup(in);
	return NULL;
}

static int
load_config_file(FILE *fp)
{
	struct opt_table conf_options[] = {
		{ "sql_server", TYPE_STRING, SET_STRING(default_cfg.sql_server) },
		{ "sql_port", TYPE_INT, SET_INT(default_cfg.sql_port) },
		{ "sql_user", TYPE_STRING, SET_STRING(default_cfg.sql_user) },
		{ "sql_password", TYPE_STRING, SET_STRING(default_cfg.sql_password) },
		{ "sql_database", TYPE_STRING, SET_STRING(default_cfg.sql_database) },
	};
	int num_conf_options = sizeof(conf_options) / sizeof(conf_options[0]);

	if (parse_conf(fp, conf_options, num_conf_options) < 0)
		return 0;

	active_cfg = malloc(sizeof(struct prog_cfg));

	/* Manually copy each config option into active_cfg. */
	active_cfg->sql_server = null_strdup(conf_options[0].val.s);
	active_cfg->sql_port = conf_options[1].val.i;
	active_cfg->sql_user = null_strdup(conf_options[2].val.s);
	active_cfg->sql_password = null_strdup(conf_options[3].val.s);
	active_cfg->sql_database = null_strdup(conf_options[4].val.s);

	free_conf(conf_options, num_conf_options);
	return 1;
}

int
read_config(const char *file)
{
	FILE *fp = NULL;

	if (file == NULL) {
		return 0;
	}

	/* User specified alternate config file, let's try that first */
	if ((fp = fopen(file, "r")) == NULL) {
		fprintf(stderr, "Couldn't open %s. No config found\n", file);
		return 0;
	}
	fprintf(stdout, "Using config file %s.\n", file);

	load_config_file(fp);
	fclose(fp);
	return 1;
}
