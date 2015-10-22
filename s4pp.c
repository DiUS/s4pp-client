#include "s4pp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define st(x) do { x } while (0)
#define return_ok      st(ctx->err = S4PP_OK; return true;)
#define return_res     st(return ctx->err == S4PP_OK && !ctx->fatal;)
#define return_err(x)  st(ctx->err = x; return false;)

#define SUPPORTED_VER "0.9"
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
  const s4pp_auth_t *auth;
  const s4pp_server_t *server;

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

  s4pp_next_fn next;
  s4pp_done_fn done;

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
  unsigned proto_errs;
} s4pp_ctx_t;


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


static void invoke_done (s4pp_ctx_t *ctx, bool success)
{
  s4pp_done_fn done = ctx->done;
  ctx->done = NULL;
  if (done)
    done (ctx, success);
}


static char *get_line_buffer (s4pp_ctx_t *ctx, unsigned len)
{
  unsigned max_payload =
    ctx->io->max_payload < UPPER_PAYLOAD_SIZE ?
      ctx->io->max_payload : UPPER_PAYLOAD_SIZE;

  if (!ctx->outbuf.bytes)
  {
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

  // Swap outbuf & overflow, *before* we get on_sent callback
  uint16_t len = ctx->outbuf.len;
  char *data = ctx->outbuf.bytes;
  ctx->outbuf.bytes = ctx->outbuf.overflow;
  ctx->outbuf.used = ctx->outbuf.overflow_used;
  ctx->outbuf.overflow = data;
  ctx->outbuf.overflow_used = 0;
  ctx->waiting_for_sent = true;

  if (!ctx->io->send (ctx->conn, data, len))
  {
    ctx->waiting_for_sent = false;
    ctx->state = S4PP_ERRORED;
    ctx->err = S4PP_NETWORK_ERROR;
    ctx->io->disconnect (ctx->conn);
    ctx->conn = NULL;
    invoke_done (ctx, false);
  }
  return false;
}


static void send_commit (s4pp_ctx_t *ctx)
{
  unsigned digest_len = ctx->digest.mech->digest_size;
  char *outbuf = get_line_buffer (ctx, 4 + digest_len * 2 + 1); // SIG:digest\n
  if (!outbuf)
    return;

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

  // SEQ:<num>,0,1,0\n  - time:0 timediv:1 datafmt:0
  unsigned max_buf_len = 4 + 10 + 6;
  char *outbuf = get_line_buffer (ctx, max_buf_len);
  if (!outbuf)
    return false;
  unsigned overreach =
    max_buf_len - sprintf (outbuf, "SEQ:%u,0,1,0\n", ctx->seq.seq_no++);
  return_buffer (ctx, overreach);
  ctx->state = S4PP_BUFFERING;

  init_hmac (ctx);
  update_hmac (ctx, ctx->authtok, strlen (ctx->authtok));
  update_hmac (ctx, outbuf, max_buf_len - overreach);
  return true;
}


static bool prepare_dict_entry (s4pp_ctx_t *ctx, const char *name, unsigned *idx)
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
    max_buf_len - sprintf (outbuf, "DICT:%u,,1,%s\n", d->idx, name);
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
  unsigned max_buf_len = 10 + 1 + 11 + val_len + 1;
  char *outbuf = get_line_buffer (ctx, max_buf_len);
  if (!outbuf)
    return;
  int32_t delta = sample->timestamp - ctx->seq.last_time;
  unsigned n;
  if (sample->type == S4PP_FORMATTED)
    n = sprintf (outbuf, "%u,%d,%s\n", dict_idx, delta, sample->val.formatted);
  else
    n = sprintf (outbuf, "%u,%d,%f\n", dict_idx, delta, sample->val.numeric);
  return_buffer (ctx, max_buf_len - n);

  ctx->seq.last_time = sample->timestamp;
  ++ctx->seq.n_sent;
  update_hmac (ctx, outbuf, n);
}


s4pp_ctx_t *s4pp_create (const s4pp_io_t *io, const digest_mech_info_t *digests, const s4pp_auth_t *auth, const s4pp_server_t *server)
{
  s4pp_ctx_t *ctx = calloc (1, sizeof (s4pp_ctx_t));
  if (ctx)
  {
    ctx->io = io;
    ctx->digests = digests;
    ctx->auth = auth;
    ctx->server = server;
  }
  return ctx;
}


static bool handle_hello (s4pp_ctx_t *ctx, char *line)
{
  char *sp = strchr (line, ' ');
  if (!sp)
    return false;
  *sp++ = 0;
  char *ver = line + 5;
  line = sp;
  sp = strchr (line, ' ');
  if (!sp)
    return false;
  *sp++ = 0;
  char *algos = line;
  char *max_samples = sp;
  if (strcmp (ver, SUPPORTED_VER) != 0)
    return false;

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

  if (ctx->digest.ctx)
    free (ctx->digest.ctx);

  ctx->digest.ctx = malloc (ctx->digest.mech->ctx_size);
  ctx->digest.mech->create (ctx->digest.ctx);

  ctx->seq.n_max = strtoul (max_samples, NULL, 0);
  ctx->state = S4PP_HELLO;
  return ctx->seq.n_max > 0;
}


static void handle_auth (s4pp_ctx_t *ctx, char *token, uint16_t len)
{
  if (ctx->authtok)
    free (ctx->authtok);

  ctx->authtok = malloc (len);
  memmove (ctx->authtok, token, len);


  unsigned digest_len = ctx->digest.mech->digest_size;
  unsigned mech_len = strlen (ctx->digest.mech->name);
  unsigned keyid_len = strlen (ctx->auth->key_id);
  // AUTH:mech,keyid,digest\n
  char outbuf[4 + 1
    + mech_len + 1
    + keyid_len + 1
    + digest_len * 2 + 1];
  char *digest =
    outbuf +
    sprintf (outbuf, "AUTH:%s,%s,", ctx->digest.mech->name, ctx->auth->key_id);
  init_hmac (ctx);
  update_hmac (ctx, ctx->auth->key_id, keyid_len);
  update_hmac (ctx, token, len);
  finalize_hmac (ctx, digest);
  crypto_encode_asciihex (digest, digest_len, digest);
  outbuf[sizeof(outbuf)-1] = '\n';

  ctx->waiting_for_sent = true;
  ctx->state = S4PP_AUTHED;
  if (!ctx->io->send (ctx->conn, outbuf, sizeof (outbuf)))
  {
// FIXME: why separate send here??
    ctx->io->disconnect (ctx->conn);
    ctx->waiting_for_sent = false;
    ctx->err = S4PP_NETWORK_ERROR; // mark as error while we reconnect
    if (!ctx->fatal)
    {
      ctx->state = S4PP_CONNECT;
      ctx->conn = ctx->io->connect (ctx->server);
    }
    else
      ctx->state = S4PP_ERRORED;
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
    invoke_done (ctx, false);
  }
  else if (strncmp ("OK:", line, 3) == 0)
  {
    if (ctx->state != S4PP_COMMITTING)
      goto protocol_error;
    ctx->proto_errs = 0;
    ctx->state = S4PP_AUTHED;
    invoke_done (ctx, true);
  }
  else
    goto protocol_error;
  return_res;

protocol_error:
  ctx->io->disconnect (ctx->conn);
  ctx->conn = NULL;
  ctx->err = S4PP_PROTOCOL_ERROR;
  ctx->state = S4PP_ERRORED;
  if (ctx->proto_errs >= MAX_PROTOCOL_ERRORS_BEFORE_FATAL)
    ctx->fatal = true; // "escape hatch" to avoid reconnect hammering
  else
    ++ctx->proto_errs;
  invoke_done (ctx, false);
  return_res;
}


bool s4pp_on_recv (s4pp_ctx_t *ctx, char *data, uint16_t len)
{
  ctx->err = S4PP_OK; // clear earlier errors

  if (!len) // remote side disconnected
  {
    ctx->io->disconnect (ctx->conn); // free the conn
    ctx->conn = NULL;
    if (ctx->state == S4PP_BUFFERING || ctx->state == S4PP_COMMITTING)
    {
      ctx->err = S4PP_SEQUENCE_NOT_COMMITTED;
      invoke_done (ctx, false);
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
    unsigned dlen = (end - data);
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
      if (!ctx->conn && !ctx->fatal)
      {
        ctx->conn = ctx->io->connect (ctx->server);
        ctx->state = S4PP_CONNECT;
      }
      break;
    case S4PP_CONNECT:
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
            unsigned idx;
            if (!prepare_dict_entry (ctx, sample.name, &idx))
              break;
            prepare_sample_entry (ctx, &sample, idx);
          }
          else if (ctx->done)
            sig = true;
          else
            break; // end of sample, no explicit commit
        }
        if (sig)
          send_commit (ctx);
      }
      break;
    case S4PP_COMMITTING:
      break; // waiting for OK/NOK, nothing to do
    case S4PP_ERRORED:
    default:
      // We have work to do, but something went wrong, so reconnect if possible
      if (ctx->conn)
        ctx->io->disconnect (ctx->conn);
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
    return_err(S4PP_ALREADY_BUSY);
  ctx->next = next;
  ctx->done = done;
  progress_work (ctx);
  return_res;
}


void s4pp_flush (s4pp_ctx_t *ctx, s4pp_done_fn done)
{
  if (ctx->state != S4PP_BUFFERING)
    done (ctx, true);
  else
  {
    ctx->done = done;
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
  free (ctx);
}
