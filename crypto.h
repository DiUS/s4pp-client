/*
 * Copyright 2019 Dius Computing Pty Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the copyright holders nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @author Johny Mattsson <jmattsson@dius.com.au>
 */
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef void (*init_crypto_ctx_fn)(void *ctx);
typedef void (*setkey_crypto_ctx_fn)(void *ctx, const void *key, size_t keylen);
typedef void (*run_crypto_ctx_fn)(void *ctx, const void *in, void *out, size_t len, bool dir_is_encrypt);
typedef void (*destroy_crypto_ctx_fn)(void *ctx);

/**
 * Description of a crypto mech.
 *
 * @c name - the name, e.g. "AES-128-CBC".
 * @c init - function to initialise a context
 * @c setkey - function to set the key for use by the context
 * @c run - function to encrypt/decrypt data
 * @c destroy - function to clean up/free a used crypto context
 * @c ctx_size - the size of a context for this mech; a memory block of at
 *   least this size must be given to the @c init function.
 * @c block_size - the block size of this mech; the keying material and
 *   data lengths must be in multiples of this block size.
 */
typedef struct
{
  const char            *name;
  init_crypto_ctx_fn     init;
  setkey_crypto_ctx_fn   setkey;
  run_crypto_ctx_fn      run;
  destroy_crypto_ctx_fn  destroy;
  uint32_t               ctx_size;
  uint16_t               block_size;
} crypto_mech_info_t;


#endif
