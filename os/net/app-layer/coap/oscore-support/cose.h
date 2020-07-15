/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      An implementation of the CBOR Object Signing and Encryption (RFC8152).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */


#ifndef _COSE_H
#define _COSE_H

#include <inttypes.h>

#include "cose/crypto.h"
#include "cose/encrypt.h"

/* COSE Encrypt0 Struct */
typedef struct cose_encrypt0_t {

  cose_encrypt_t crypt;
  cose_key_t key;

  uint8_t partial_iv[8];
  size_t partial_iv_len;

  uint8_t *kid_context;
  size_t kid_context_len;

} cose_encrypt0_t;

/* Initiate a new COSE Encrypt0 object. */
void cose_encrypt0_init(cose_encrypt0_t *ptr);

/* Return length */
size_t cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer);
void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

/* Return length */
size_t cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, uint8_t **buffer);
void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

#endif /* _COSE_H */
