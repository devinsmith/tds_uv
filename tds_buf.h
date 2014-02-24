/* Copyright (C) 2003-2005, Claudio Leite
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the BSF Software Project nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */

/* This code is based on Claudio Leite's packet.c file inside the
 * imcomm module of his bsflite program. Claudio states that his code was
 * inspired by libfaim's (now defunct) bstream (binary stream)
 * implementation.
 */

#ifndef __TDS_BUF_H_
#define __TDS_BUF_H__

#include <sys/types.h>
#include <stdint.h>
#include <uv.h>

#include "tds_uv.h"

/* TDS Packet Header Status (see spec 2.2.3.1.2) */
#define TDS_NORMAL 0x00
#define TDS_EOM 0x01

/* packet creation functions */
void buf_raw_init(uv_buf_t *buf, size_t len);
void buf_tds_init(uv_buf_t *buf, size_t len, uint8_t type, uint8_t sta_type);
void buf_addraw(uv_buf_t *p, const unsigned char *bytes, size_t len);
void buf_addzero(uv_buf_t *p, int num_zeros);
void buf_add8(uv_buf_t *p, uint8_t val);
void buf_add16(uv_buf_t *p, uint16_t val);
void buf_add16_le(uv_buf_t *p, uint16_t val);
void buf_add32(uv_buf_t *p, uint32_t val);
void buf_add32_le(uv_buf_t *p, uint32_t val);
void buf_addstring(uv_buf_t *p, const char *bytes);
void buf_free(uv_buf_t * p);
void buf_set_hdr(uv_buf_t *p);

uint8_t buf_get8(struct connection *conn);
uint16_t buf_get16(struct connection *conn);
uint16_t buf_get16_le(struct connection *conn);

#endif /* __TDS_BUF_H__ */

