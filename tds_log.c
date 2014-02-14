/*
 * Copyright (c) 2008-2014 Devin Smith <devin@devinsmith.net>
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

/* TDS debug logging implementation. */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "tds_log.h"

static int tds_global_loglevel;
static FILE *tds_global_logfp;

static void
tds_debug_destroy(void)
{
	if (tds_global_logfp != NULL) {
		fflush(tds_global_logfp);
		fclose(tds_global_logfp);
	}
}

void
tds_debug_init(void)
{
	tds_global_loglevel = 0;
	tds_global_logfp = NULL;

	atexit(tds_debug_destroy);
}

void
tds_debug_set_log_level(int lvl)
{
	tds_global_loglevel = lvl;
}

FILE *
tds_debug_get_fp(void)
{
	return tds_global_logfp;
}

void
tds_debug_set_log_file(const char *file)
{
	tds_global_logfp = fopen(file, "w");
}

void
tds_debug(int lvl, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (tds_global_loglevel >= lvl) {
		if (tds_global_logfp) {
			vfprintf(tds_global_logfp, fmt, ap);
			fflush(tds_global_logfp);
		} else {
			vfprintf(stdout, fmt, ap);
		}
	}
	va_end(ap);
	return;
}

