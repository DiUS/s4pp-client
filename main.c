#include "s4pp.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

struct s4pp_server
{
  const char *hostname;
  uint16_t port;
};

struct s4pp_conn
{
  int sockfd;
};

static s4pp_conn_t *do_conn (const s4pp_server_t *server)
{
  (void)server;
  struct addrinfo *addrs;
  if (getaddrinfo (server->hostname, NULL, NULL, &addrs) != 0)
    return NULL;

  int sock;
  struct addrinfo *ai;
  for (ai = addrs; ai; ai = ai->ai_next)
  {
    sock = socket (ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock == -1)
      continue;
    if (connect (sock, ai->ai_addr, ai->ai_addrlen) != -1)
      break;
    else
      close (sock);
  }
  if (!ai)
    return NULL;
  freeaddrinfo (addrs);

  // TODO: set a timeout in case server never sends anything

  s4pp_conn_t *conn = malloc (sizeof (s4pp_conn_t));
  if (conn)
    conn->sockfd = sock;
  else
    close (sock);
  return conn;
}


static void do_disconn (s4pp_conn_t *conn)
{
  (void)conn;
  // TODO
}


static bool do_send (s4pp_conn_t *conn, const char *data, uint16_t len)
{
  (void)conn;
  (void)data;
  (void)len;
  // TODO
  return false;
}


static void on_done (s4pp_ctx_t *ctx, bool success)
{
  (void)ctx;
  (void)success;
}

int main (int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  s4pp_io_t io = { do_conn, do_disconn, do_send, 1400 };
  s4pp_auth_t auth = { "keyid", (uint8_t*)"keydata", 7 }; // TODO
  s4pp_server_t server = { "localhost", /* TODO */ 22226 };
  s4pp_ctx_t *ctx = s4pp_create (&io, crypto_all_mechs (), &auth, &server);
  if (!ctx)
    return 1;

  s4pp_flush (ctx, on_done);

  s4pp_destroy (ctx);
  return 0;
}
