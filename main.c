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
#include "tiny-AES-c/aes.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <poll.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>
#include <stdio.h>
#include <assert.h>

#define info(x...) do { if (verbose) fprintf(stderr,x); } while (0)
#define warn(x...) do { info(x); syslog(LOG_WARNING, x); } while (0)

#define SAMPLE_THRESHOLD_HI 5000
#define SAMPLE_THRESHOLD_LO 2000

static int data_format = 0;

struct s4pp_server
{
  const char *hostname;
  const char *port;
};

struct s4pp_conn
{
  int sockfd;
  char *outq;
  size_t outlen;
};


static volatile bool terminate;
static volatile bool eof;
static volatile bool errored;

static s4pp_ctx_t *ctx;

enum { POLLFD_SAMPLES, POLLFD_SOCK, POLLFD_MAX };
static struct
{
  struct pollfd pollfd[POLLFD_MAX];
  s4pp_conn_t *conn;
} io;

static struct
{
  char *bytes;
  size_t len;
} inbuf;


typedef struct sample_list
{
  s4pp_sample_t sample;
  char *line;
  struct sample_list *next;
} sample_list_t;
static sample_list_t *samples;
static sample_list_t *last_sample;
static sample_list_t *last_pulled_sample;
static unsigned sample_count;

static bool verbose;
static bool no_notify;

static int commit_interval = 30;
static time_t next_commit;


static void on_quit (int sig)
{
  (void)sig;
  terminate = true;
}


static void on_usr1 (int sig)
{
  (void)sig;
  syslog (LOG_INFO,
    "%u queued samples, %zu bytes in buffer, next commit at %ld (%s), "
    "io.pollfd[].fd = { %d, %d }",
    sample_count, inbuf.len, next_commit, ctime (&next_commit),
    io.pollfd[0].fd, io.pollfd[1].fd);
}


static void out_of_mem (void)
{
  fprintf (stderr, "Error: out of memory, terminating.\n");
  syslog (LOG_ERR, "out of memory, terminating");
  exit (3);
}


static int get_poll_timeout (void)
{
  time_t now = time (NULL);
  if (commit_interval > 0)
  {
    if (now >= next_commit)
        return 0;
     else
       return (next_commit - now) * 1000;
  }
  else
      return -1;
}


static char *get_line (void)
{
  char *nl = memchr (inbuf.bytes, '\n', inbuf.len);
  char *line = 0;
  if (nl)
  {
    *nl = 0;
    line = strdup (inbuf.bytes);
    size_t linelen = nl - inbuf.bytes + 1; // including \0
    memmove (inbuf.bytes, inbuf.bytes + linelen, inbuf.len - linelen);
    inbuf.len -= linelen;
    if (linelen > 1 && line[linelen -2] == '\r')
      line[linelen -2] = 0;
    return line;
  }
  else
    return NULL;
}


static void on_checkpoint (s4pp_ctx_t *ctx, bool success, unsigned num_items)
{
  (void)ctx;
  if (success)
  {
    while (samples != last_pulled_sample)
    {
      sample_list_t *sl = samples->next;
      free (samples->line);
      free (samples);
      samples = sl;
    }
    if (last_pulled_sample)
    {
      samples = last_pulled_sample->next;
      free (last_pulled_sample->line);
      free (last_pulled_sample);
    }
    sample_count -= num_items;
    if (!sample_count)
      last_sample = NULL;
    info ("Committed %u samples (%u still queued)\n", num_items, sample_count);
  }
  else
    info ("Commit failed: code %d\n", s4pp_last_error (ctx));
  last_pulled_sample = NULL;
}


static bool next_sample (s4pp_ctx_t *ctx, s4pp_sample_t *sample)
{
  (void)ctx;
  sample_list_t *sl = last_pulled_sample ? last_pulled_sample->next : samples;
  if (!sl)
    return false;
  *sample = sl->sample;
  last_pulled_sample = sl;
  return true;
}


static void process_inbuf (void)
{
  char *line;
  sample_list_t **sample_next = last_sample ? &last_sample->next : &samples;
  while ((line = get_line ()))
  {
    char *t = strtok (line, ",");
    const char *span = (data_format == 1) ? strtok (NULL, ",") : "0";
    char *name = strtok (NULL, ",");
    char *val = strtok (NULL, "");
    if (!t || !name || !val)
    {
      if (data_format == 0)
        warn ("Bad sample format: %s,%s,%s\n", t, name, val);
      else
        warn ("Bad sample format: %s,%s,%s,%s\n", t, span, name, val);
      continue;
    }
    sample_list_t *sl = calloc (1, sizeof (sample_list_t));
    if (!sl)
      out_of_mem ();
    sl->line = line; // now with a few \0 in it
    sl->sample.timestamp = strtoul (t, NULL, 0);
    sl->sample.span = strtoul (span, NULL, 0);
    sl->sample.name = name;
    sl->sample.val.formatted = val;
    sl->sample.type = S4PP_FORMATTED;
    sl->sample.divisor = 1;
    *sample_next = sl;
    sample_next = &sl->next;
    last_sample = sl;
    ++sample_count;
  }
  if (sample_count >= SAMPLE_THRESHOLD_HI)
    io.pollfd[POLLFD_SAMPLES].events &= ~POLLIN; // pause input
}


static void flush_on_pull_done(s4pp_ctx_t *ctx)
{
  s4pp_flush (ctx);
}

static void handle_poll_timeout (void)
{
  next_commit = time (NULL) + commit_interval;

  if (samples)
  {
    if (!s4pp_pull (ctx, next_sample, flush_on_pull_done))
    {
      if (s4pp_last_error (ctx) != S4PP_ALREADY_BUSY)
        errored = true;
      else
        info ("Upload still running... (%u samples to go)\n", sample_count);
    }
    else
      info ("Uploading %u+ samples...\n", sample_count);
  }
}



static void handle_sample_input (void)
{
  char buf[2048];
  ssize_t ret;
  while ((ret = read (io.pollfd[POLLFD_SAMPLES].fd, buf, sizeof (buf))) < 0)
  {
    if (errno == EINTR)
      continue;
    else
      goto end_of_samples;
  }
  if (ret == 0)
    goto end_of_samples;

  inbuf.bytes = realloc (inbuf.bytes, inbuf.len + ret);
  if (inbuf.bytes)
  {
    memmove (inbuf.bytes + inbuf.len, buf, ret);
    inbuf.len += ret;
  }
  else
    out_of_mem ();

  process_inbuf ();
  return;

end_of_samples:
  info ("End of input, waiting for samples to drain.\n");
  eof = true;
  io.pollfd[POLLFD_SAMPLES].fd = -1;
}


static s4pp_conn_t *do_conn (const s4pp_server_t *server)
{
  struct addrinfo hints = { 0 };
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;
  struct addrinfo *addrs;
  if (getaddrinfo (server->hostname, server->port, &hints, &addrs) != 0)
    return NULL;

  int sock = -1;
  for (struct addrinfo *ai = addrs; ai; ai = ai->ai_next)
  {
    sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock == -1)
      continue;

    int enable = 1;
    setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));

    if (connect (sock, ai->ai_addr, ai->ai_addrlen) == 0)
      break;
    close (sock);
    sock = -1;
  }
  if (sock == -1)
  {
    warn ("Failed to connect to %s:%s\n", server->hostname, server->port);
    return NULL;
  }
  freeaddrinfo (addrs);

  // TODO: set a timeout in case server never sends anything

  io.conn = calloc (1, sizeof (s4pp_conn_t));
  if (io.conn)
  {
    fcntl (sock, F_SETFL, O_NONBLOCK);
    io.conn->sockfd = sock;
    io.pollfd[POLLFD_SOCK].fd = sock;
    io.pollfd[POLLFD_SOCK].events = POLLIN;
    info ("Connected to %s:%s\n", server->hostname, server->port);
  }
  else
    close (sock);
  return io.conn;
}


static void do_disconn (s4pp_conn_t *conn)
{
  info ("Disconnect\n");
  io.pollfd[POLLFD_SOCK].fd = -1;
  io.pollfd[POLLFD_SOCK].events = 0;
  io.pollfd[POLLFD_SOCK].revents = 0;
  io.conn = NULL;
  close (conn->sockfd);
  free (conn->outq);
  free (conn);
}


static bool do_send (s4pp_conn_t *conn, const char *data, uint16_t len)
{
  if (!conn)
    return false;
  // We'll want to call s4pp_on_sent from the main loop, so flag POLLOUT
  io.pollfd[POLLFD_SOCK].events |= POLLOUT;
  ssize_t written;
  while ((written = write (conn->sockfd, data, len)) != len)
  {
    if (written == -1)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        char *buf = malloc (len);
        if (!buf)
          out_of_mem ();
        memmove (buf, data, len);
        free (conn->outq); // only free after copy, as might copy from outq!
        conn->outq = buf;
        conn->outlen = len;
        return true;
      }
      return false;
    }
    else
    {
      len -= written;
      data += written;
    }
  }
  // if we get here we've sent everything we wanted, which *may* have been
  // from the outq, so clear it to avoid resends
  free (conn->outq);
  conn->outq = NULL;
  conn->outlen = 0;
  return true;
}


static void handle_sock_input (void)
{
  if (io.pollfd[POLLFD_SOCK].revents & POLLOUT)
  {
    io.pollfd[POLLFD_SOCK].events &= ~POLLOUT;
    if (io.conn && io.conn->outq)
      do_send (io.conn, io.conn->outq, io.conn->outlen);
    else
      errored |= !s4pp_on_sent (ctx);
  }
  if (io.pollfd[POLLFD_SOCK].revents & POLLIN)
  {
    char buf[2048];
    ssize_t ret;
    while ((ret = read (io.pollfd[POLLFD_SOCK].fd, buf, sizeof (buf))) < 0)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return; // "impossible"
      errored |= !s4pp_on_recv (ctx, NULL, 0); // error, drop the connection
      return;
    }
    errored |= !s4pp_on_recv (ctx, buf, (uint16_t)ret);
  }
  if (io.conn &&
      io.pollfd[POLLFD_SOCK].revents & (POLLHUP | POLLERR | POLLNVAL))
    errored |= !s4pp_on_recv (ctx, NULL, 0); // connection dead
}


static void on_notify (s4pp_ctx_t *ctx, unsigned code, unsigned nargs, const char **args)
{
  (void)ctx;
  static const char *known[] = { "TIME", "FIRMWARE", "FLAGS" };
  printf ("NOTIFY\t");
  if (code < (sizeof (known) / sizeof (known[0])))
    printf ("%s", known[code]);
  else
    printf ("%u", code);
  for (unsigned i = 0; i < nargs; ++i)
    printf ("\t%s", args[i]);
  printf ("\n");
}


static void rnd (uint8_t *out, size_t len)
{
  for (size_t n = 0; n < len; )
  {
    int ret = getrandom (out + n, len - n, 0);
    if (ret > 0)
      n += ret;
    else if (ret < 0 && errno != EINTR)
    {
      perror ("unable to generate random bytes");
      abort ();
    }
  }
}

// Wrappers for tiny-AES-c
void aes128_init (void *ctx) {
  memset (ctx, 0, sizeof (struct AES_ctx));
}

void aes128_setkey (void *ctx, const void *key, size_t keylen)
{
  assert(keylen == 16);
  AES_init_ctx ((struct AES_ctx *)ctx, (const uint8_t *)key);
}

void aes128_run (void *ctx, const void *in, void *out, size_t len, bool dir_is_encrypt)
{
  struct AES_ctx *aes = (struct AES_ctx *)ctx;
  if (out != in)
    memcpy (out, in, len);
  if (dir_is_encrypt)
    AES_CBC_encrypt_buffer (aes, out, len);
  else
    AES_CBC_decrypt_buffer (aes, out, len);
}

void aes128_destroy (void *ctx)
{
  (void)ctx;
}


static crypto_mech_info_t cryptos[] = {
  {
    .name       = "AES-128-CBC",
    .init       = aes128_init,
    .setkey     = aes128_setkey,
    .run        = aes128_run,
    .destroy    = aes128_destroy,
    .ctx_size   = sizeof (struct AES_ctx),
    .block_size = 16
  },
  { .name = NULL, }
};


static int syntax (const char *pname)
{
  fprintf (stderr,
    "Syntax: %s [-h] | -u <user> -k <keyfile> -s <server> [-p <port>] [-i <upload_interval>] [-v] [-H] [-H] [-F 0/1]\n",
    pname);
  return 2;
}


int main (int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  signal (SIGINT, on_quit);
  signal (SIGTERM, on_quit);
  signal (SIGPIPE, SIG_IGN);
  signal (SIGUSR1, on_usr1);

  io.pollfd[POLLFD_SOCK].fd = -1;

  io.pollfd[POLLFD_SAMPLES].fd = STDIN_FILENO;
  io.pollfd[POLLFD_SAMPLES].events = POLLIN;

  s4pp_io_t ios = { do_conn, do_disconn, do_send, 1400 };
  s4pp_auth_t auth = { 0, };
  s4pp_server_t server = { 0, "22226" };
  int hide_opt = 0;

  int opt;
  while ((opt = getopt (argc, argv, "u:k:s:p:i:vnhHF:")) != -1)
  {
    switch (opt)
    {
      case 'h': return syntax (argv[0]);
      case 'u': auth.key_id = optarg; break;
      case 'k':
      {
        int fd = open (optarg, O_RDONLY);
        auth.key_len = lseek (fd, 0, SEEK_END);
        auth.key_bytes = mmap (0, auth.key_len, PROT_READ, MAP_PRIVATE, fd, 0);
        break;
      }
      case 's': server.hostname = optarg; break;
      case 'p': server.port = optarg; break;
      case 'i':
        commit_interval = atoi (optarg);
        next_commit = time(NULL) + commit_interval;
        break;
      case 'v': verbose = true; break;
      case 'n': no_notify = true; break;
      case 'H': ++hide_opt; break;
      case 'F': data_format = atoi (optarg); break;
      default:
        verbose = true;
        info ("Unknown option '%c'\n", opt);
        return 1;
    }
  }

  if (!auth.key_id || !auth.key_bytes || !server.hostname)
    return syntax (argv[0]);

fresh_start:
  errored = false;
  ctx = s4pp_create (&ios, crypto_all_mechs (), cryptos, rnd, &auth, &server, S4PP_HIDE_DISABLED + hide_opt, data_format, NULL);
  if (!ctx)
  {
    warn ("failed to create s4pp context, exiting");
    return 1;
  }
  if (!no_notify)
    s4pp_set_notification_handler (ctx, on_notify);
  s4pp_set_commit_handler (ctx, on_checkpoint);

  while (!terminate && !errored)
  {
    io.pollfd[POLLFD_SOCK].revents = 0;
    io.pollfd[POLLFD_SAMPLES].revents = 0;

    if (sample_count <= SAMPLE_THRESHOLD_LO)
      io.pollfd[POLLFD_SAMPLES].events |= POLLIN; // unpause input

    if (eof && sample_count == 0)
    {
      terminate = true;
      break;
    }

    int ret = poll (io.pollfd, POLLFD_MAX, get_poll_timeout ());
    time_t now = time (NULL);
    // prioritise kicking off uploads, lest we get stuck processing stdin
    if (ret == 0 || now > next_commit)
      handle_poll_timeout ();
    else if (ret > 0)
    {
      if (io.pollfd[POLLFD_SOCK].revents)
        handle_sock_input ();
      if (io.pollfd[POLLFD_SAMPLES].revents)
        handle_sample_input ();
    }
    else if (errno == EINTR)
      continue;
    else
      break;
  }
  if (!terminate)
  {
    warn ("%s error (%d), restarting...\n",
      errored ? "S4PP" : "Poll",
      errored ? (int)s4pp_last_error (ctx) : errno);
    s4pp_destroy (ctx);
    goto fresh_start;
  }

  s4pp_destroy (ctx);
  info ("Done.\n");
  free(inbuf.bytes); // to assist valgrinding
  return 0;
}
