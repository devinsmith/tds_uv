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

#ifndef __TDS_CONSTANTS_H__
#define __TDS_CONSTANTS_H__

/* The TDS protocol column/row types */
#define TDS_INT4_TYPE 0x38
#define TDS_DATETIME_TYPE 0x3D
#define TDS_BIGVARCHAR_TYPE 0xA7

/* TDS packet types (defined in 2.2.3.1.1) */
#define TDS_SQL_BATCH 0x01
#define TDS_RPC 0x03
#define TDS_RESULT 0x04
#define TDS_LOGIN 0x10
#define TDS_PRELOGIN 0x12

#endif /* __TDS_CONSTANTS_H__ */

