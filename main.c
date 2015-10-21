#include "s4pp.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <poll.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include <stdio.h>

#define info(x...) do { if (verbose) printf(x); } while (0)

struct s4pp_server
{
  const char *hostname;
  const char *port;
};

struct s4pp_conn
{
  int sockfd;
};


static volatile bool terminate;
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
  char *lastline;
} inbuf;

static bool verbose;


static void on_quit (int sig)
{
  (void)sig;
  terminate = true;
}


static int get_poll_timeout (void)
{
  return -1; // TODO
}


static void handle_sock_input (void)
{
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
    }
    errored |= !s4pp_on_recv (ctx, buf, (uint16_t)ret);
  }
  if (io.pollfd[POLLFD_SOCK].revents & (POLLHUP | POLLERR | POLLNVAL))
    errored |= !s4pp_on_recv (ctx, NULL, 0); // connection dead
}


static char *get_line (void)
{
  char *nl = memchr (inbuf.bytes, '\n', inbuf.len);
  if (nl)
  {
    *nl = 0;
    free (inbuf.lastline);
    inbuf.lastline = strdup (inbuf.bytes);
    size_t linelen = nl - inbuf.bytes + 1; // including \0
    memmove (inbuf.bytes, inbuf.bytes + linelen, inbuf.len - linelen);
    inbuf.len -= linelen;
    if (linelen > 1 && inbuf.lastline[linelen -2] == '\r')
      inbuf.lastline[linelen -2] = 0;
    return inbuf.lastline;
  }
  else
    return NULL;
}


static void handle_poll_timeout (void)
{
  // TODO
}


static void handle_sample_input (void)
{
  char buf[2048];
  ssize_t ret;
  while ((ret = read (io.pollfd[POLLFD_SAMPLES].fd, buf, sizeof (buf))) < 0)
  {
    if (errno == EINTR)
      continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return; // "impossible"
  }
  if (ret == 0)
  {
    if (!inbuf.len || !memchr (inbuf.bytes, '\n', inbuf.len))
      terminate = true; // eol on input, and no more lines buffered
    return;
  }
  // TODO: limit buffer size
  inbuf.bytes = realloc (inbuf.bytes, inbuf.len + ret);
  if (inbuf.bytes)
  {
    memmove (inbuf.bytes + inbuf.len, buf, ret);
    inbuf.len += ret;
  }
  else
    errored = true; // TODO: just exit with a message?
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
    if (connect (sock, ai->ai_addr, ai->ai_addrlen) == 0)
      break;
    close (sock);
    sock = -1;
  }
  if (sock == -1)
  {
    info("warn: failed to connect to %s:%s\n", server->hostname, server->port);
    return NULL;
  }
  freeaddrinfo (addrs);

  // TODO: set a timeout in case server never sends anything

  io.conn = malloc (sizeof (s4pp_conn_t));
  if (io.conn)
  {
    fcntl (sock, F_SETFL, O_NONBLOCK);
    io.conn->sockfd = sock;
    io.pollfd[POLLFD_SOCK].fd = sock;
    io.pollfd[POLLFD_SOCK].events = POLLIN;
  }
  else
    close (sock);
  return io.conn;
}


static void do_disconn (s4pp_conn_t *conn)
{
  io.pollfd[POLLFD_SOCK].fd = -1;
  io.conn = NULL;
  close (conn->sockfd);
  free (conn);
}


static bool do_send (s4pp_conn_t *conn, const char *data, uint16_t len)
{
  ssize_t written;
  while ((written = write (conn->sockfd, data, len)) != len)
  {
    if (written == -1)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        io.pollfd[POLLFD_SOCK].events |= POLLOUT;
        int ret;
        // secondary event loop, while waiting for sock to become writable
        while (true)
        {
          io.pollfd[POLLFD_SOCK].revents = 0;
          io.pollfd[POLLFD_SAMPLES].revents = 0;
          ret = poll (io.pollfd, POLLFD_MAX, get_poll_timeout ());
          if (ret < 0)
          {
            if (ret == EINTR)
              continue;
            else
              return false;
          }
          else if (ret > 0)
          {
            // prioritise handling of writable sock to minimise complexity
            if (io.pollfd[POLLFD_SOCK].revents & POLLOUT)
              break;
            if (io.pollfd[POLLFD_SOCK].revents & (POLLERR | POLLHUP | POLLNVAL))
              return false;

            if (io.pollfd[POLLFD_SAMPLES].revents)
              handle_sample_input ();
            if (io.pollfd[POLLFD_SOCK].revents)
              handle_sock_input ();
          }
          else
            handle_poll_timeout ();
        }
        io.pollfd[POLLFD_SOCK].events &= ~POLLOUT;
      }
      else
        return false;
    }
    else
    {
      len -= written;
      data += written;
    }
  }
  errored |= !s4pp_on_sent (ctx);
  return true;
}


static bool next_sample (s4pp_ctx_t *ctx, s4pp_sample_t *sample)
{
  (void)ctx;
  char *line;
get_a_line:
  while (!(line = get_line ()))
  {
    int ret = poll (io.pollfd, POLLFD_MAX, get_poll_timeout ());
    if (ret < 0)
    {
      if (errno == EINTR && !terminate)
        continue;
      else
      {
        errored |= !terminate;
        return false;
      }
    }
    if (ret == 0)
      handle_poll_timeout ();
    if (io.pollfd[POLLFD_SAMPLES].revents)
      handle_sample_input ();
    if (io.pollfd[POLLFD_SOCK].revents)
      handle_sock_input ();
    if (terminate)
      return false;
  }
  char *t = strtok (line, ",");
  char *name = strtok (NULL, ",");
  char *val = strtok (NULL, ",");
  if (!t || !name || !val)
    goto get_a_line; // bad formatting, skip it

  sample->timestamp = strtoul (t, NULL, 0);
  sample->name = name;
  sample->val.formatted = val;
  sample->type = S4PP_FORMATTED;
  return true;
}


static void final_flush_done (s4pp_ctx_t *ctx, bool success)
{
  (void)ctx;
  info("Flush %s\n", success ? "ok." : "failed.");
  terminate = true;
}


static int syntax (const char *pname)
{
  fprintf (stderr,
    "Syntax: %s [-h] | -u <user> -k <keyfile> -s <server> [-p <port>\n",
    pname);
  return 2;
}


int main (int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  signal (SIGINT, on_quit);
  signal (SIGTERM, on_quit);

  io.pollfd[POLLFD_SOCK].fd = -1;

  io.pollfd[POLLFD_SAMPLES].fd = STDIN_FILENO;
  io.pollfd[POLLFD_SAMPLES].events = POLLIN;

  s4pp_io_t ios = { do_conn, do_disconn, do_send, 1400 };
  s4pp_auth_t auth = { 0, }; //{ "johny", (uint8_t*)"FIXME", 5 }; // TODO
  s4pp_server_t server = { 0, "22226" };

  int opt;
  while ((opt = getopt (argc, argv, "u:k:s:p:vh")) != -1)
  {
    switch (opt)
    {
      case 'h': return syntax (argv[0]);
      case 'u': auth.key_id = optarg; break;
      case 'k': // TODO load key from file
      {
        int fd = open (optarg, O_RDONLY);
        auth.key_len = lseek (fd, 0, SEEK_END);
        auth.key_bytes = mmap (0, auth.key_len, PROT_READ, MAP_PRIVATE, fd, 0);
        break;
      }
      case 's': server.hostname = optarg; break;
      case 'p': server.port = optarg; break;
      case 'v': verbose = true; break;
      default:
        verbose = true;
        info("unknown option '%c'\n", opt);
        return 1;
    }
  }

  if (!auth.key_id || !auth.key_bytes || !server.hostname)
    return syntax (argv[0]);

  int restart_wait;

fresh_start:
  restart_wait = time (NULL) + 5;
  errored = false;
  ctx = s4pp_create (&ios, crypto_all_mechs (), &auth, &server);
  if (!ctx)
    return 1;

  s4pp_pull (ctx, next_sample, NULL);

  while (!terminate && !errored)
  {

    io.pollfd[POLLFD_SOCK].revents = 0;
    io.pollfd[POLLFD_SAMPLES].revents = 0;
    int ret = poll (io.pollfd, POLLFD_MAX, get_poll_timeout ());
    if (ret > 0)
    {
      if (io.pollfd[POLLFD_SAMPLES].revents)
        handle_sample_input ();
      if (io.pollfd[POLLFD_SOCK].revents)
        handle_sock_input ();

      if (!io.conn && restart_wait < time (NULL))
      {
        info("Connection lost, restarting...\n");
        s4pp_destroy (ctx);
        goto fresh_start;
      }
    }
    else if (ret == 0)
      handle_poll_timeout ();
    else if (errno == EINTR)
      continue;
    else
      errored = true;
  }
  if (!terminate && errored)
  {
    info("Unexpected error, restarting...\n");
    s4pp_destroy (ctx);
    goto fresh_start;
  }

  if (!errored)
  {
    info("Flushing sample buffer...\n");
    terminate = false;
    s4pp_flush (ctx, final_flush_done);
    // TODO: set timeout for flush
    io.pollfd[POLLFD_SAMPLES].fd = -1; // not listening for more samples
    while (!terminate && !errored)
    {
      io.pollfd[POLLFD_SOCK].revents = 0;
      int ret = poll (io.pollfd, POLLFD_MAX, get_poll_timeout ());
      if (ret > 0 && io.pollfd[POLLFD_SOCK].revents)
        handle_sock_input ();
      else if (ret == -1 && errno == EINTR)
        continue;
      else
        break; // ok, we failed, just exit
    }
  }

  s4pp_destroy (ctx);
  info("Done.\n");
  return 0;
}
