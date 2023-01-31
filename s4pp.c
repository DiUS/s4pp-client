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
#include "s4pp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define st(x) do { x } while (0)
#define return_ok      st(ctx->err = S4PP_OK; return true;)
#define return_res     st(return ctx->err == S4PP_OK && !ctx->fatal;)
#define return_err(x)  st(ctx->err = x; return false;)

#define MAX_PROTOCOL_ERRORS_BEFORE_FATAL 5
#define UPPER_PAYLOAD_SIZE 1400 // to be further reduced by io.max_payload

typedef struct dict_entry
{
  struct dict_entry *next;
  unsigned idx;
  char name[];
} dict_entry_t;

typedef struct s4pp_ctx
{
  const s4pp_io_t *io;
  const digest_mech_info_t *digests;
  const crypto_mech_info_t *cryptos;
  const s4pp_auth_t *auth;
  const s4pp_server_t *server;

  s4pp_rnd_fn random;
  int data_format;
  void *user_arg;

  s4pp_conn_t *conn;

  char *authtok;

  struct
  {
    char *bytes;
    unsigned len;
  } inbuf;

  struct
  {
    char *bytes;
    unsigned len;
    unsigned used;
    char *overflow;
    unsigned overflow_used;
  } outbuf;

  bool waiting_for_sent;
  bool want_commit_on_sent;
  unsigned num_items;

  struct
  {
    time_t last_time;
    unsigned seq_no;
    unsigned n_max;
    unsigned n_sent;
    dict_entry_t *dict;
  } seq;

  struct
  {
    const digest_mech_info_t *mech;
    void *ctx;
  } digest;

  struct {
    const crypto_mech_info_t *mech;
    void *ctx;
    char *from;
  } hide;
  s4pp_hide_mode_t hide_mode;

  s4pp_next_fn next;
  s4pp_done_fn done;
  s4pp_ntfy_fn ntfy;
  s4pp_on_commit_fn commit;

  enum {
    S4PP_INIT,
    S4PP_CONNECT,
    S4PP_HELLO,
    S4PP_AUTHED,
    S4PP_BUFFERING,
    S4PP_COMMITTING,
    S4PP_ERRORED
  } state;

  s4pp_error_t err;
  bool fatal;
  bool destroy_prohibited;
  bool destroy_delayed;
  unsigned proto_errs;
} s4pp_ctx_t;

static void progress_work (s4pp_ctx_t *ctx);

static void do_hmac_pad (s4pp_ctx_t *ctx, uint8_t padval)
{
  const digest_mech_info_t *mech = ctx->digest.mech;
  unsigned klen = ctx->auth->key_len;
  const uint8_t *key = ctx->auth->key_bytes;
  uint8_t altkey[mech->digest_size];
  if (klen > mech->block_size)
  {
    crypto_hash (mech, key, ctx->auth->key_len, altkey);
    key = altkey;
    klen = mech->digest_size;
  }
  uint8_t pad[mech->block_size];
  memset (pad, padval, sizeof (pad));
  for (unsigned i = 0; i < klen; ++i)
    pad[i] ^= key[i];

  mech->update (ctx->digest.ctx, pad, sizeof (pad));
}


static void init_hmac (s4pp_ctx_t *ctx)
{
  ctx->digest.mech->create (ctx->digest.ctx);
  do_hmac_pad (ctx, 0x36);
}


static void update_hmac (s4pp_ctx_t *ctx, const char *data, unsigned len)
{
  ctx->digest.mech->update (ctx->digest.ctx, data, len);
}


static void finalize_hmac (s4pp_ctx_t *ctx, char *dst)
{
  const digest_mech_info_t *mech = ctx->digest.mech;
  char digest[mech->digest_size];
  mech->finalize (digest, ctx->digest.ctx);

  mech->create (ctx->digest.ctx);
  do_hmac_pad (ctx, 0x5c);
  mech->update (ctx->digest.ctx, digest, sizeof (digest));
  mech->finalize (dst, ctx->digest.ctx);
}


static void clear_dict (s4pp_ctx_t *ctx)
{
  while (ctx->seq.dict)
  {
    dict_entry_t *tmp = ctx->seq.dict->next;
    free (ctx->seq.dict);
    ctx->seq.dict = tmp;
  }
}


static void invoke_done (s4pp_ctx_t *ctx)
{
  ctx->next = NULL;

  s4pp_done_fn done = ctx->done;
  ctx->done = NULL;
  if (done)
    done (ctx);
}


static void invoke_committed(s4pp_ctx_t *ctx, bool result)
{
  unsigned num_items = ctx->num_items;
  ctx->num_items = 0;

  if (ctx->commit)
    ctx->commit (ctx, result, num_items);

  if (!result)
    invoke_done (ctx);
}


static void hide_pad(s4pp_ctx_t *ctx)
{
  if (!ctx->hide.mech)
    return;

  uint16_t skip =
    (ctx->hide.from > ctx->outbuf.bytes &&
     ctx->hide.from < ctx->outbuf.bytes + ctx->outbuf.used) ?
    ctx->hide.from - ctx->outbuf.bytes : 0;

  // Pad to a full block if necessary (we know the size of the output
  // buffers is a multiple of the blocksize, so we won't overrun here).
  uint16_t used_in = ctx->outbuf.used;
  while ((ctx->outbuf.used - skip) % ctx->hide.mech->block_size)
    ctx->outbuf.bytes[ctx->outbuf.used++] = '\n';

  uint16_t padlen = ctx->outbuf.used - used_in;
  // This is the critical part - we need to hmac the padding before
  // the returned line buffer gets filled and its content hmac'd.
  if (ctx->state == S4PP_BUFFERING && padlen > 0)
    update_hmac (ctx, ctx->outbuf.bytes + used_in, padlen);
}


static char *get_line_buffer (s4pp_ctx_t *ctx, unsigned len)
{
  if (!ctx->outbuf.bytes)
  {
    unsigned max_payload =
      ctx->io->max_payload < UPPER_PAYLOAD_SIZE ?
        ctx->io->max_payload : UPPER_PAYLOAD_SIZE;
    if (ctx->hide.mech)
      max_payload -= max_payload % ctx->hide.mech->block_size;

    ctx->outbuf.bytes = malloc (max_payload);
    if (!ctx->outbuf.bytes)
      goto no_mem;
    ctx->outbuf.len = max_payload;
    ctx->outbuf.used = 0;
  }
  if (!ctx->outbuf.overflow)
  {
    ctx->outbuf.overflow = malloc (ctx->outbuf.len);
    if (!ctx->outbuf.overflow)
      goto no_mem;
    ctx->outbuf.overflow_used = 0;
  }

  if (len > ctx->outbuf.len)
    goto no_mem;

  unsigned avail = ctx->outbuf.len - ctx->outbuf.used;
  char *buf = ctx->outbuf.bytes + ctx->outbuf.used;
  if (ctx->outbuf.overflow_used || len > avail)
  {
    if (ctx->hide.mech && !ctx->outbuf.overflow_used)
      hide_pad (ctx);

    buf = ctx->outbuf.overflow + ctx->outbuf.overflow_used;
    ctx->outbuf.overflow_used += len;
  }
  else
    ctx->outbuf.used += len;
  return buf;

no_mem:
  ctx->state = S4PP_ERRORED;
  ctx->err = S4PP_NO_MEMORY;
  return NULL;
}


static void return_buffer (s4pp_ctx_t *ctx, unsigned len)
{
  if (ctx->outbuf.overflow_used)
    ctx->outbuf.overflow_used -= len;
  else
    ctx->outbuf.used -= len;
}


/// @returns true if space left in outbuf false if overflow in use + outbuf sent
static bool process_out_buffer (s4pp_ctx_t *ctx, bool flush)
{
  if (ctx->waiting_for_sent)
    return false;

  if (ctx->outbuf.used < ctx->outbuf.len &&
      !ctx->outbuf.overflow_used &&
      !flush)
    return true;

  // Much of the time the padding has already been done in the overflow
  // handling, but post-SIG padding needs get caught here
  if (ctx->hide.mech)
    hide_pad (ctx);

  // Swap outbuf & overflow, *before* we get on_sent callback
  uint16_t used = ctx->outbuf.used;
  char *data = ctx->outbuf.bytes;
  ctx->outbuf.bytes = ctx->outbuf.overflow;
  ctx->outbuf.used = ctx->outbuf.overflow_used;
  ctx->outbuf.overflow = data;
  ctx->outbuf.overflow_used = 0;
  ctx->waiting_for_sent = true;

  if (ctx->hide.mech)
  {
    char *to_encrypt = ctx->hide.from > data && ctx->hide.from < (data + used) ?
      ctx->hide.from : data;

    ctx->hide.mech->run (
      ctx->hide.ctx, to_encrypt, to_encrypt, used - (to_encrypt - data), true);
    ctx->hide.from = 0;
}

  if (!ctx->io->send (ctx->conn, data, used))
  {
    ctx->waiting_for_sent = false;
    ctx->state = S4PP_ERRORED;
    ctx->err = S4PP_NETWORK_ERROR;
    if (ctx->conn)
      ctx->io->disconnect (ctx->conn);
    ctx->conn = NULL;
    invoke_committed (ctx, false);
  }
  return false;
}


static void send_commit (s4pp_ctx_t *ctx)
{
  unsigned digest_len = ctx->digest.mech->digest_size;
  char *outbuf = get_line_buffer (ctx, 4 + digest_len * 2 + 1); // SIG:digest\n
  if (!outbuf)
    return; // rely on connection failing later; FIXME

  strcpy (outbuf, "SIG:");
  char *digest = outbuf + 4;
  finalize_hmac (ctx, digest);
  crypto_encode_asciihex (digest, digest_len, digest);
  digest[digest_len * 2] = '\n';

  ctx->state = S4PP_COMMITTING;
  process_out_buffer (ctx, true);
}


static bool prepare_begin_seq (s4pp_ctx_t *ctx)
{
  clear_dict (ctx);
  ctx->seq.last_time = 0;
  ctx->seq.n_sent = 0;

  // SEQ:<num>,0,1,<x>\n  - time:0 timediv:1 datafmt:x
  unsigned max_buf_len = 4 + 10 + 5 + 10 + 1;
  char *outbuf = get_line_buffer (ctx, max_buf_len);
  if (!outbuf)
    return false;
  unsigned overreach =
    max_buf_len - sprintf (
      outbuf, "SEQ:%u,0,1,%d\n", ctx->seq.seq_no++, ctx->data_format);
  return_buffer (ctx, overreach);
  ctx->state = S4PP_BUFFERING;

  init_hmac (ctx);
  update_hmac (ctx, ctx->authtok, strlen (ctx->authtok));
  update_hmac (ctx, outbuf, max_buf_len - overreach);
  return true;
}


static bool prepare_dict_entry (s4pp_ctx_t *ctx, const char *name, unsigned divisor, unsigned *idx)
{
  for (dict_entry_t *d = ctx->seq.dict; d; d = d->next)
  {
    if (strcmp (name, d->name) == 0)
    {
      *idx = d->idx;
      return true;
    }
  }
  unsigned len = strlen (name);
  dict_entry_t *d = malloc (sizeof (dict_entry_t) + len + 1);
  if (!d)
  {
    ctx->state = S4PP_ERRORED;
    ctx->err = S4PP_NO_MEMORY;
    return false;
  }
  strcpy (d->name, name);
  d->next = ctx->seq.dict;
  d->idx = d->next ? d->next->idx + 1 : 0;
  ctx->seq.dict = d;

  // DICT:<idx>,,1,<name>\n
  unsigned max_buf_len = 5 + 10 + 4 + len + 1;
  char *outbuf = get_line_buffer (ctx, max_buf_len);
  if (!outbuf)
    return false;
  unsigned overreach =
    max_buf_len - sprintf (outbuf, "DICT:%u,,%u,%s\n", d->idx, divisor, name);
  return_buffer (ctx, overreach);

  update_hmac (ctx, outbuf, max_buf_len - overreach);
  *idx = d->idx;
  return true;
}


static void prepare_sample_entry (s4pp_ctx_t *ctx, const s4pp_sample_t *sample, unsigned dict_idx)
{
  unsigned val_len =
    sample->type == S4PP_FORMATTED ?
      strlen (sample->val.formatted) :
      (unsigned)snprintf (NULL, 0, "%f", sample->val.numeric);
  // <idx>,<delta-t>,<span>,<val>[,<val...>]\n
  unsigned max_buf_len = 10 + 1 + 11 + 1 + 10 + 1 + val_len + 1 + 1;
  char *outbuf = get_line_buffer (ctx, max_buf_len);
  if (!outbuf)
    return;
  int delta = sample->timestamp - ctx->seq.last_time;
  unsigned n = 0;
  switch (ctx->data_format)
  {
    case 0: n = sprintf (outbuf, "%u,%d,", dict_idx, delta); break;
    case 1:
      n = sprintf (outbuf, "%u,%d,%u,", dict_idx, delta, sample->span); break;
  }
  if (sample->type == S4PP_FORMATTED)
    n += sprintf (outbuf + n, "%s\n", sample->val.formatted);
  else
    n += sprintf (outbuf + n, "%f\n", sample->val.numeric);
  return_buffer (ctx, max_buf_len - n);

  ctx->seq.last_time = sample->timestamp;
  ++ctx->seq.n_sent;
  update_hmac (ctx, outbuf, n);
}


s4pp_ctx_t *s4pp_create (const s4pp_io_t *io, const digest_mech_info_t *digests, const crypto_mech_info_t *cryptos, s4pp_rnd_fn rnd_fn, const s4pp_auth_t *auth, const s4pp_server_t *server, s4pp_hide_mode_t hide_mode, int data_format, void *user_arg)
{
  if (data_format != 0 && data_format != 1)
    return NULL;

  s4pp_ctx_t *ctx = calloc (1, sizeof (s4pp_ctx_t));
  if (ctx)
  {
    ctx->io = io;
    ctx->digests = digests;
    ctx->cryptos = cryptos;
    ctx->random = rnd_fn;
    ctx->auth = auth;
    ctx->server = server;
    ctx->hide_mode = hide_mode;
    ctx->data_format = data_format;
    ctx->user_arg = user_arg;
  }
  return ctx;
}


static inline uint8_t decodehexnibble (char h) {
  if (h >= '0' && h <= '9')
    return h - '0';
  if (h >= 'a' && h <= 'f')
    return h - 'a' + 10;
  else if (h >= 'A' && h < 'F')
    return h - 'A' + 10;
  else
    return 0;
}


static inline uint8_t decodehexbyte (const char *hex) {
  return (decodehexnibble (hex[0]) << 4) | decodehexnibble (hex[1]);
}


static void create_session_key (s4pp_ctx_t *ctx, const char *token, uint16_t len)
{
  uint16_t bs = ctx->hide.mech->block_size;
  if (len > bs * 2)
    len = bs * 2;
  if (len & 1)
    --len; // dont' attempt to decode half hex bytes

  uint8_t buf[bs];
  for (int i = 0; i < bs; ++i)
  {
    if (i < len)
      buf[i] = decodehexbyte (token + i*2);
    else
      buf[i] = '\n';
  }

  uint8_t crypto_ctx[ctx->hide.mech->ctx_size];
  ctx->hide.mech->init (crypto_ctx);
  ctx->hide.mech->setkey (crypto_ctx, ctx->auth->key_bytes, bs);
  ctx->hide.mech->run (crypto_ctx, buf, buf, bs, true);
  ctx->hide.mech->destroy (crypto_ctx);

  ctx->hide.mech->setkey (ctx->hide.ctx, buf, bs);
}


static bool handle_hello (s4pp_ctx_t *ctx, char *line)
{
  // S4PP/x.y <algo,...> <max_samples> [hidealgo,...]
  char *sp = strchr (line, ' ');
  if (!sp)
    return false;
  *sp++ = 0;
  if (strncmp("S4PP/1.", line, 7) != 0)
    return false;
  // GCC 11 appears confused and complains that 7 is of char type below??
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wchar-subscripts"
  bool is_v1_2plus = (strlen(line) == 8 && isdigit(line[7]) && line[7] >= '2');
  #pragma GCC diagnostic pop
  line = sp;
  sp = strchr (line, ' ');
  if (!sp)
    return false;
  *sp++ = 0;
  const char *algos = line;
  const char *max_samples = sp;
  const char *hide_algos = NULL;
  if (is_v1_2plus)
  {
    sp = strchr (max_samples, ' ');
    if (!sp)
      return false;
    *sp++ = 0;
    hide_algos = sp;
  }

  ctx->digest.mech = NULL;
  for (const digest_mech_info_t *m = ctx->digests; m->name; ++m)
  {
    if (strstr (algos, m->name))
    {
      ctx->digest.mech = m;
      break;
    }
  }
  if (!ctx->digest.mech)
  {
    ctx->fatal = true; // we can't talk to this server, don't reconnect
    return false;
  }

  if (ctx->hide_mode != S4PP_HIDE_DISABLED && hide_algos)
  {
    for (const crypto_mech_info_t *m = ctx->cryptos; m->name; ++m)
    {
      if (strstr (hide_algos, m->name))
      {
        ctx->hide.mech = m;
        break;
      }
    }
  }
  if (ctx->hide_mode == S4PP_HIDE_MANDATORY && !ctx->hide.mech)
  {
    ctx->fatal = true; // we can't talk to this server, don't reconnect
    return false;
  }

  free (ctx->digest.ctx);
  ctx->digest.ctx = malloc (ctx->digest.mech->ctx_size);
  ctx->digest.mech->create (ctx->digest.ctx);

  if (ctx->hide.mech)
  {
    free (ctx->hide.ctx);
    ctx->hide.ctx = calloc (1, ctx->hide.mech->ctx_size);
    ctx->hide.mech->init (ctx->hide.ctx);
  }

  ctx->seq.n_max = strtoul (max_samples, NULL, 0);
  ctx->state = S4PP_HELLO;
  return ctx->seq.n_max > 0;
}


static void handle_auth (s4pp_ctx_t *ctx, char *token, uint16_t len)
{
  if (ctx->authtok)
    free (ctx->authtok);

  ctx->authtok = calloc (1, len +1);
  memmove (ctx->authtok, token, len);


  unsigned digest_len = ctx->digest.mech->digest_size;
  unsigned mech_len = strlen (ctx->digest.mech->name);
  unsigned keyid_len = strlen (ctx->auth->key_id);
  // AUTH:mech,keyid,digest\n
  const unsigned auth_str_len =
    4 + 1 + mech_len + 1 + keyid_len + 1 + digest_len*2 + 1;
  // HIDE:mech\n
  const unsigned hide_str_len =
    (ctx->hide.mech ? 5 + strlen(ctx->hide.mech->name) + 1 : 0);
  char outbuf[auth_str_len + hide_str_len];
  char *digest =
    outbuf +
    sprintf (outbuf, "AUTH:%s,%s,", ctx->digest.mech->name, ctx->auth->key_id);
  init_hmac (ctx);
  update_hmac (ctx, ctx->auth->key_id, keyid_len);
  update_hmac (ctx, token, len);
  finalize_hmac (ctx, digest);
  crypto_encode_asciihex (digest, digest_len, digest);
  outbuf[auth_str_len-1] = '\n';

  if (ctx->hide.mech)
  {
    if (ctx->auth->key_len >= ctx->hide.mech->block_size)
    {
      create_session_key (ctx, token, len);
      sprintf (outbuf + auth_str_len, "HIDE:%s\n", ctx->hide.mech->name);
    }
    else
      ctx->hide.mech = NULL;
  }

  ctx->waiting_for_sent = true;
  ctx->state = S4PP_AUTHED;
  if (!ctx->io->send (ctx->conn, outbuf, sizeof (outbuf)))
  {
    if (ctx->conn)
      ctx->io->disconnect (ctx->conn);
    ctx->conn = NULL;
    ctx->waiting_for_sent = false;
    ctx->err = S4PP_NETWORK_ERROR; // mark as error while we reconnect
    if (!ctx->fatal)
    {
      ctx->state = S4PP_CONNECT;
      ctx->conn = ctx->io->connect (ctx->server);
    }
    else
      ctx->state = S4PP_ERRORED;
    return;
  }

  if (ctx->hide.mech)
  {
    // generate salt line
    size_t bs = ctx->hide.mech->block_size;
    uint8_t buf[bs];

    ctx->random (buf, bs);
    for (unsigned i = 0; i < bs; ++i)
    {
      while (buf[i] == '\n')
        ctx->random (&buf[i], 1);
    }

    uint8_t n = bs / 2 + (buf[bs-1] % (bs / 2));
    buf[n++] = '\n';

    char *line = get_line_buffer (ctx, n);
    if (line)
    {
      // Since we do an explicit send above we could probably do without
      // support for skipping encryption of the first part of the buffer,
      // but it's already written, so...
      ctx->hide.from = line;
      memcpy (line, buf, n);
      update_hmac (ctx, line, n);
    }
  }
}


static bool handle_line (s4pp_ctx_t *ctx, char *line, uint16_t len)
{
  if (line[len -1] == '\n')
    line[len -1] = 0;
  else
    goto protocol_error;
  if (strncmp ("S4PP/", line, 5) == 0)
  {
    // S4PP/x.y <algo,algo...> <max_samples>
    if (ctx->state != S4PP_CONNECT || !handle_hello (ctx, line))
      goto protocol_error;
  }
  else if (strncmp ("TOK:", line, 4) == 0)
  {
    if (ctx->state == S4PP_HELLO)
      handle_auth (ctx, line + 4, len - 5); // len - 5 => ditch \0
    else
      goto protocol_error;
  }
  else if (strncmp ("REJ:", line, 4) == 0)
    goto protocol_error;
  else if (strncmp ("NOK:", line, 4) == 0)
  {
    if (ctx->state != S4PP_COMMITTING)
      goto protocol_error;
    // we don't pipeline sequences, so don't need to check the seqno
    ctx->state = S4PP_AUTHED;
    ctx->err = S4PP_SEQUENCE_NOT_COMMITTED;
    invoke_committed (ctx, false);
  }
  else if (strncmp ("OK:", line, 3) == 0)
  {
    if (ctx->state != S4PP_COMMITTING)
      goto protocol_error;
    ctx->proto_errs = 0;
    ctx->state = S4PP_AUTHED;

    ctx->destroy_prohibited = true;
    invoke_committed (ctx, true);
    ctx->destroy_prohibited = false;
    if (ctx->destroy_delayed)
      s4pp_destroy(ctx);
    else
      progress_work(ctx);
  }
  else if (strncmp ("NTFY:", line, 5) == 0)
  {
    char *argsp = 0;
    unsigned long code = strtoul (line + 5, &argsp, 10);
    unsigned nargs = 0;
    for (char *p = argsp; *p; ++p)
      if (*p == ',')
        ++nargs;
    const char **args = malloc (sizeof (char *) * (nargs + 1));
    if (args)
    {
      unsigned i = 0;
      for (char *p = argsp; *p; ++p)
      {
        if (*p == ',')
        {
          args[i++] = p + 1;
          *p = 0;
        }
      }
      args[i] = 0; // Be nice and leave a null at the end of args array
      if (ctx->ntfy)
        ctx->ntfy (ctx, (unsigned)code, nargs, args);
      free (args);
    }
    // else silently ignore it? or whinge somehow? TODO
  }
  else
    goto protocol_error;
  return_res;

protocol_error:
  if (ctx->conn)
    ctx->io->disconnect (ctx->conn);
  ctx->conn = NULL;
  ctx->err = S4PP_PROTOCOL_ERROR;
  ctx->state = S4PP_ERRORED;
  if (ctx->proto_errs >= MAX_PROTOCOL_ERRORS_BEFORE_FATAL)
    ctx->fatal = true; // "escape hatch" to avoid reconnect hammering
  else
    ++ctx->proto_errs;
  invoke_committed (ctx, false);
  return_res;
}


bool s4pp_on_recv (s4pp_ctx_t *ctx, char *data, uint16_t len)
{
  ctx->err = S4PP_OK; // clear earlier errors

  if (!len) // remote side disconnected
  {
    if (ctx->conn)
      ctx->io->disconnect (ctx->conn); // free the conn
    ctx->conn = NULL;
    if (ctx->state == S4PP_BUFFERING || ctx->state == S4PP_COMMITTING)
    {
      ctx->err = S4PP_SEQUENCE_NOT_COMMITTED;
      invoke_committed (ctx, false);
      return_res;
    }
    else
      return_ok;
  }

  char *nl = memchr (data, '\n', len);

  // deal with joining with previous chunk
  if (ctx->inbuf.len)
  {
    char *end = nl ? nl : data + len - 1;
    unsigned dlen = (end - data) + 1;
    unsigned newlen = ctx->inbuf.len + dlen;
    ctx->inbuf.bytes = realloc (ctx->inbuf.bytes, newlen);
    if (!ctx->inbuf.bytes)
    {
      ctx->inbuf.len = 0;
      ctx->state = S4PP_ERRORED; // we just lost bytes, can't recover
      return_err (S4PP_NO_MEMORY);
    }
    memmove (ctx->inbuf.bytes + ctx->inbuf.len, data, dlen);
    ctx->inbuf.len += dlen;
    data += dlen;
    len -= dlen;
    if (!handle_line (ctx, ctx->inbuf.bytes, ctx->inbuf.len))
      return_res;
    else
    {
      free (ctx->inbuf.bytes);
      ctx->inbuf.bytes = NULL;
      ctx->inbuf.len = 0;
      nl = memchr (data, '\n', len);
    }
  }
  // handle full lines inside 'data'
  while (nl)
  {
    unsigned dlen = (nl - data) + 1;
    if (!handle_line (ctx, data, dlen))
      return_res;

    data += dlen;
    len -= dlen;
    nl = memchr (data, '\n', len);
  }
  // deal with left-over pieces
  if (len)
  {
    ctx->inbuf.bytes = malloc (len);
    if (!ctx->inbuf.bytes) // we just lost bytes, can't recover
    {
      ctx->state = S4PP_ERRORED;
      return_err (S4PP_NO_MEMORY);
    }
    else
      ctx->inbuf.len = len;
  }

  return_res;
}


static void progress_work (s4pp_ctx_t *ctx)
{
  switch (ctx->state)
  {
    case S4PP_INIT:
    case S4PP_CONNECT: // if connect failed, we need to retry the connect
      if (!ctx->conn && !ctx->fatal)
      {
        ctx->conn = ctx->io->connect (ctx->server);
        ctx->state = S4PP_CONNECT;
      }
      break;
    case S4PP_HELLO:
      break; // waiting for hello, nothing to do
    case S4PP_AUTHED:
      if (!ctx->next)
        break; // nothing to do, leave the session alone
      if (!prepare_begin_seq (ctx))
        break;
      // else fall-through
    case S4PP_BUFFERING:
      while (ctx->state == S4PP_BUFFERING && process_out_buffer (ctx, false))
      {
        bool sig = false;
        if (ctx->seq.n_sent >= ctx->seq.n_max)
          sig = true;
        else
        {
          s4pp_sample_t sample;
          if (ctx->next (ctx, &sample))
          {
            if (sample.type==S4PP_RESERVATION)
            {
              if (ctx->seq.n_sent+sample.val.reservation >= ctx->seq.n_max)
                sig = true;
            }
            else
            {
              unsigned idx;
              if (!prepare_dict_entry (ctx, sample.name, sample.divisor, &idx))
                break;
              prepare_sample_entry (ctx, &sample, idx);
              ++ctx->num_items;
            }
          }
          else
          {
            invoke_done(ctx);
            break;
          }
        }
        if (sig)
          send_commit (ctx);
      }
      break;
    case S4PP_COMMITTING: // waiting for OK/NOK
      // we might only have buffered the SIG: in the overflow area, so
      // ensure we flush it out in that case.
      if (ctx->outbuf.used)
          process_out_buffer (ctx, true);
      break;
    case S4PP_ERRORED:
    default:
      // We have work to do, but something went wrong, so reconnect if possible
      if (ctx->conn)
        ctx->io->disconnect (ctx->conn);
      ctx->conn = NULL;
      ctx->err = S4PP_OK;
      if (!ctx->fatal)
      {
        ctx->conn = ctx->io->connect (ctx->server);
        ctx->state = S4PP_CONNECT;
      }
      else
        ctx->state = S4PP_ERRORED;
      break;
  }
}


bool s4pp_on_sent (s4pp_ctx_t *ctx)
{
  ctx->err = S4PP_OK; // clear earlier errors
  ctx->waiting_for_sent = false;
  if (ctx->want_commit_on_sent)
  {
    ctx->want_commit_on_sent = false;
    send_commit (ctx);
  }
  else
    progress_work (ctx);
  return_res;
}


bool s4pp_pull (s4pp_ctx_t *ctx, s4pp_next_fn next, s4pp_done_fn done)
{
  if (ctx->next || ctx->done)
  {
    progress_work (ctx);
    return_err(S4PP_ALREADY_BUSY);
  }
  ctx->next = next;
  ctx->done = done;
  progress_work (ctx);
  return_res;
}


void s4pp_flush (s4pp_ctx_t *ctx)
{
  if (ctx->state != S4PP_BUFFERING)
    invoke_committed (ctx, true);
  else
  {
    if (ctx->waiting_for_sent)
      ctx->want_commit_on_sent = true;
    else
      send_commit (ctx);
  }
}


s4pp_error_t s4pp_last_error (s4pp_ctx_t *ctx)
{
  // Once ctx->fatal is set, it sticks
  return ctx->fatal ? S4PP_FATAL_ERROR : ctx->err;
}


void s4pp_destroy (s4pp_ctx_t *ctx)
{
  if (!ctx)
    return;
  if (ctx->destroy_prohibited)
  {
    ctx->destroy_delayed=true;
    return;
  }
  clear_dict (ctx);
  if (ctx->conn)
    ctx->io->disconnect (ctx->conn);
  if (ctx->authtok)
    free (ctx->authtok);
  if (ctx->inbuf.bytes)
    free (ctx->inbuf.bytes);
  if (ctx->outbuf.bytes)
    free (ctx->outbuf.bytes);
  if (ctx->outbuf.overflow)
    free (ctx->outbuf.overflow);
  if (ctx->digest.ctx)
    free (ctx->digest.ctx);
  if (ctx->hide.ctx)
    free (ctx->hide.ctx);
  free (ctx);
}


void s4pp_set_notification_handler (s4pp_ctx_t *ctx, s4pp_ntfy_fn fn)
{
  if (!ctx)
    return;
  ctx->ntfy = fn;
}


void s4pp_set_commit_handler (s4pp_ctx_t *ctx, s4pp_on_commit_fn fn)
{
  if (!ctx)
    return;
  ctx->commit = fn;
}


void *s4pp_user_arg(s4pp_ctx_t *ctx)
{
  return ctx->user_arg;
}
