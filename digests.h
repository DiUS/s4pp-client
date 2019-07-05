/*
 * Copyright 2015-2019 Dius Computing Pty Ltd. All rights reserved.
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
#ifndef _CRYPTO_DIGESTS_H_
#define _CRYPTO_DIGESTS_H_

#include <stdint.h>
#include <sys/types.h>

typedef void (*create_ctx_fn)(void *ctx);
typedef void (*update_ctx_fn)(void *ctx, const void *msg, int len);
typedef void (*finalize_ctx_fn)(void *digest, void *ctx);

/**
 * Description of a message digest mechanism.
 *
 * Typical usage (if not using the crypto_xxxx() functions below):
 *   digest_mech_info_t *mi = crypto_digest_mech (chosen_algorithm);
 *   void *ctx = os_malloc (mi->ctx_size);
 *   mi->create (ctx);
 *   mi->update (ctx, data, len);
 *   ...
 *   uint8_t *digest = os_malloc (mi->digest_size);
 *   mi->finalize (digest, ctx);
 *   ...
 *   os_free (ctx);
 *   os_free (digest);
 */
typedef struct
{
  const char *    name;
  create_ctx_fn   create;
  update_ctx_fn   update;
  finalize_ctx_fn finalize;
  uint32_t        ctx_size;
  uint32_t        digest_size;
  uint32_t        block_size;
} digest_mech_info_t;


/** @returns a zero-terminated array of digest mechs */
const digest_mech_info_t *crypto_all_mechs (void);

/**
 * Looks up the mech data for a specified digest algorithm.
 * @param mech The name of the algorithm, e.g. "MD5", "SHA256"
 * @returns The mech data, or null if the mech is unknown.
 */
const digest_mech_info_t *crypto_digest_mech (const char *mech);

/**
 * Wrapper function for performing a one-in-all hashing operation.
 * @param mi       A mech from @c crypto_digest_mech(). A null pointer @c mi
 *                 is harmless, but will of course result in an error return.
 * @param data     The data to create a digest for.
 * @param data_len Number of bytes at @c data to digest.
 * @param digest   Output buffer, must be at least @c mi->digest_size in size.
 * @return 0 on success, non-zero on error.
 */
int crypto_hash (const digest_mech_info_t *mi, const void *data, size_t data_len, uint8_t *digest);


/**
 * Perform ASCII Hex encoding. Does not null-terminate the buffer.
 *
 * @param bin     The buffer to ascii-hex encode.
 * @param bin_len Number of bytes in @c bin to encode.
 * @param outbuf  Output buffer, must be at least @c bin_len*2 bytes in size.
 *                Note that in-place encoding is supported, and as such
 *                bin==outbuf is safe, provided the buffer is large enough.
 */
void crypto_encode_asciihex (const char *bin, size_t bin_len, char *outbuf);


#endif
