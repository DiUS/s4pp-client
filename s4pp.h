#ifndef _S4PP_H_
#define _S4PP_H_

#include <stdint.h>
#include <stdbool.h>
#include "digests.h"

typedef struct s4pp_ctx s4pp_ctx_t; // opaque to all but s4pp.c
typedef struct s4pp_conn s4pp_conn_t; // opaque from s4pp's point of view
typedef struct s4pp_server s4pp_server_t; // opaque from s4pp's point of view

/**
 * All S4PP I/O is done indirectly via program-provided I/O functions,
 * in order to make s4pp.c readily reusable.
 *
 * The connect() function is invoked whenever a new connection needs to be
 * established. It's only argument is the s4pp_server_t pointer passed
 * initialy to s4pp_create(). This struct may be defined in whichever
 * manner makes sense for a particular implementation. Typically it would
 * include members for server address and port number.
 * The function returns a pointer to another opaque structure, s4pp_conn,
 * which will be provided back to the disconnect() & send() functions.
 * Again, this struct may be defined in whichever way makes sense, e.g.
 * holding a file descriptor or perhaps a TLS session handle. If a
 * connection cannot be started, this function must return NULL.
 *
 * The disconnect() function is expected to terminate the connection and
 * free all resources related to conn. No further references to conn will
 * be made by the s4pp module.
 *
 * The send() function requests data to be sent on the connection. If the
 * data is successfully queued for transmission, the function returns true.
 * Once the data has been sent, the s4pp_on_sent() function is expected to
 * be called to progress the session. This may be done directly from
 * within the s4pp_io.send() call, if applicable.
 *
 * The max_payload member indicates the largest payload the send() function
 * is willing to accept.
 */
typedef struct s4pp_io
{
  s4pp_conn_t *(*connect) (const s4pp_server_t *server);
  void (*disconnect) (s4pp_conn_t *conn);
  bool (*send) (s4pp_conn_t *conn, const char *data, uint16_t len);
  uint16_t max_payload;
} s4pp_io_t;


/**
 * Authentication material for S4PP.
 * key_id is the utf-8 string identifying the key used.
 * key_bytes points to the keying material, of key_len bytes.
 */
typedef struct s4pp_auth
{
  char *key_id;
  uint8_t *key_bytes;
  unsigned key_len;
} s4pp_auth_t;

/**
 * Create a new S4PP context.
 * @param io The I/O functions to use. See @c s4pp_io for details.
 * @param digests An array of available digest mechanisms, including at least
 *   SHA256. Array is terminated by a null record (digests[n].name == NULL).
 *   The array should be sorted in preference order, with the most desirable
 *   mechanism first.
 * @param server Remote address information which will be given (possibly
 *   repeatedly) to io.connect().
 * @returns a new S4PP context, or null if one could not be allocated.
 */
s4pp_ctx_t *s4pp_create (const s4pp_io_t *io, const digest_mech_info_t *digests, const s4pp_auth_t *auth, const s4pp_server_t *server);

/**
 * To be called when new data has arrived on the associated connection.
 * If the connection has been closed by the remote end, indicate this
 * by calling with len == 0, which will result in the s4pp module
 * calling the registered io.disconnect() function to free the associated
 * s4pp_conn_t.
 * @param ctx The s4pp context.
 * @param data The bytes received.
 * @param len Number of bytes available.
 * @returns true unless an unhandled error is pending. See @c s4pp_last_error().
 */
bool s4pp_on_recv (s4pp_ctx_t *ctx, char *data, uint16_t len);

/**
 * To be called when requested data has been fully sent.
 * @param ctx The s4pp context.
 * @returns true unless an error occurred. See @c s4pp_last_error().
 */
bool s4pp_on_sent (s4pp_ctx_t *ctx);


/**
 * Each sample to be transmitted is described by the sensor name, a timestamp
 * and the value itself. The value may be a preformatted string or a regular
 * double value. The type enum determines which is being used.
 */
typedef struct s4pp_sample
{
  const char *name;
  time_t timestamp;
  union {
    const char *formatted;
    double numeric;
  } val;
  enum { S4PP_FORMATTED, S4PP_NUMERIC } type;
} s4pp_sample_t;



/**
 * Callback prototype for signalling a commit result.
 * @param ctx The s4pp context.
 * @param success True if the commit was successful, false otherwise.
 */
typedef void (*s4pp_done_fn) (s4pp_ctx_t *ctx, bool success);

/**
 * Callback prototype for pulling the next sample to send.
 * @param ctx The s4pp context.
 * @param sample The sample struct to fill in with the next sample data.
 * @return true if a sample was provided, false if no sample was available.
 */
typedef bool (*s4pp_next_fn) (s4pp_ctx_t *ctx, s4pp_sample_t *sample);

/**
 * Commences an upload where each sample will be "pulled" via the next()
 * callback. If done is non-NULL, the current sequence will be committed on
 * reaching the end of samples (when next() returns false).
 * @param ctx The s4pp context.
 * @param next The sample source function.
 * @param done The commit function. NULL if not wanting to force commit.
 * @returns true if the pull operation could be commenced.
 */
bool s4pp_pull (s4pp_ctx_t *ctx, s4pp_next_fn next, s4pp_done_fn done);

/**
 * Requests an explicit commit of the current sequence (if any), overriding
 * any pending commit/done function registered.
 * @param ctx The s4pp context.
 * @param done The callback to invoke when the commit result is available.
 *   If no sequence was open when s4pp_flush() is called, this callback is
 *   invoked right away with a success indication.
 */
void s4pp_flush (s4pp_ctx_t *ctx, s4pp_done_fn done);

/**
 * Destroys an s4pp context and frees all associated resources.
 * Any in-progress sequences are aborted without notifications.
 * @param ctx The s4pp context.
 */
void s4pp_destroy (s4pp_ctx_t *ctx);

typedef enum
{
  S4PP_OK,
  S4PP_NO_MEMORY,
  S4PP_NETWORK_ERROR,
  S4PP_PROTOCOL_ERROR,
  S4PP_FATAL_ERROR, /* server not compatible */
  S4PP_ALREADY_BUSY,
  S4PP_SEQUENCE_NOT_COMMITTED,
} s4pp_error_t;

/**
 * Queries the last error seen on the given context.
 * @param ctx The s4pp context.
 * @returns the last error.
 */
s4pp_error_t s4pp_last_error (s4pp_ctx_t *ctx);

#endif
