/*
 * Copyright (c) 2015, DiUS Computing Pty Ltd (jmattsson@dius.com.au)
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
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include "digests.h"
#include "sha2.h"
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>

#define MECH(pfx, u, ds, bs) \
  { #pfx, \
    (create_ctx_fn)pfx ## u ## Init, \
    (update_ctx_fn)pfx ## u ## Update, \
    (finalize_ctx_fn)pfx ## u ## Final, \
    sizeof(pfx ## _CTX), \
    ds, \
    bs }

static const digest_mech_info_t hash_mechs[] =
{
  MECH(SHA256, _ , SHA256_DIGEST_LENGTH, SHA256_BLOCK_LENGTH),
  MECH(SHA384, _ , SHA384_DIGEST_LENGTH, SHA384_BLOCK_LENGTH),
  MECH(SHA512, _ , SHA512_DIGEST_LENGTH, SHA512_BLOCK_LENGTH),
  { 0 }
};

#undef MECH

const digest_mech_info_t *crypto_all_mechs (void)
{
  return hash_mechs;
}

const digest_mech_info_t *crypto_digest_mech (const char *mech)
{
  if (!mech)
    return 0;

  size_t i;
  for (i = 0; i < (sizeof (hash_mechs) / sizeof (digest_mech_info_t)); ++i)
  {
    const digest_mech_info_t *mi = hash_mechs + i;
    if (strcasecmp (mech, mi->name) == 0)
      return mi;
  }
  return 0;
}

const char crypto_hexbytes[] = "0123456789abcdef";

// note: supports in-place encoding
void crypto_encode_asciihex (const char *bin, size_t binlen, char *outbuf)
{
  size_t aidx = binlen * 2 -1;
  int i;
  for (i = binlen -1; i >= 0; --i)
  {
    outbuf[aidx--] = crypto_hexbytes[bin[i] & 0xf];
    outbuf[aidx--] = crypto_hexbytes[bin[i] >>  4];
  }
}


int crypto_hash (const digest_mech_info_t *mi,
  const void *data, size_t data_len,
  uint8_t *digest)
{
  if (!mi)
    return EINVAL;

  void *ctx = (void *)malloc (mi->ctx_size);
  if (!ctx)
    return ENOMEM;

  mi->create (ctx);
  mi->update (ctx, data, data_len);
  mi->finalize (digest, ctx);

  free (ctx);
  return 0;
}
