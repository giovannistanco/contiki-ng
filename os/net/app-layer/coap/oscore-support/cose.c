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


#include "cose.h"
#include "oscore-crypto.h"
#include "string.h"


/* Initiate a new COSE Encrypt0 object. */
void
cose_encrypt0_init(cose_encrypt0_t *cose)
{
  memset(cose, 0, sizeof(cose_encrypt0_t));

  cose_encrypt_init(&cose->crypt, COSE_FLAGS_ENCRYPT0);
  cose_key_init(&cose->key);
}

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size)
{
  if(size > sizeof(ptr->partial_iv)){
	  return;
  }
  memcpy(ptr->partial_iv, buffer, size);
  ptr->partial_iv_len = size;
}

/* Return length */
size_t
cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer)
{
  *buffer = ptr->partial_iv;
  return ptr->partial_iv_len;
}

size_t cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, uint8_t **buffer){
  *buffer = ptr->kid_context;
  return ptr->kid_context_len;
}

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size){
  ptr->kid_context = buffer;
  ptr->kid_context_len = size;
} 
