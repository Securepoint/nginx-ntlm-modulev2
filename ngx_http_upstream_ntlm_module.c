/*
 * ngx_http_upstream_ntlm_module.c — nginx NTLM upstream module v2
 *
 * Binds an upstream connection to a client connection for the duration of an
 * NTLM/Negotiate authentication handshake and keeps the upstream connection
 * alive across subsequent requests from the same client.
 *
 * Targets nginx >= 1.25.  Does not support older nginx releases.
 *
 * ── Security invariants ────────────────────────────────────────────────────
 *
 *  I1. in_cache is the authoritative ownership flag for a cache item.
 *      in_cache == 1  →  item lives in conf->cache and owns peer_connection.
 *      in_cache == 0  →  item lives in conf->free  (idle slot, no connection).
 *      Every code path that moves an item out of conf->cache MUST call
 *      ngx_http_upstream_ntlm_item_release(), which atomically clears
 *      in_cache, peer_connection, and client_connection before any queue
 *      operation, so that any concurrently running handler sees a consistent
 *      state and exits early.
 *
 *  I2. c->read->data (not c->data) stores the cache item while an upstream
 *      connection is idle.  nginx's ngx_http_upstream_handler() requires
 *      c->data to be the request pointer; overwriting it with the cache item
 *      causes a segfault on nginx >= 1.25.  c->read->data is restored to c
 *      (the connection) before the connection is returned to upstream core.
 *
 *  I3. OOM guard: if ngx_pool_cleanup_add() returns NULL the upstream
 *      connection MUST NOT be inserted into the cache.  Without a cleanup
 *      handler the cached item would retain a stale client_connection pointer
 *      that nginx may later recycle for a different client, allowing
 *      get_ntlm_peer to hand an already-authenticated upstream session to the
 *      wrong client (ABA pointer-reuse session hijack).
 *
 *  I4. Stale-credential eviction: when a new NTLM/Negotiate Authorization
 *      header arrives on a keep-alive client connection whose upstream session
 *      has already completed its handshake (c->requests >= 2), the old
 *      authenticated upstream session is evicted and closed.  This prevents
 *      a different identity from silently reusing a prior authenticated
 *      context.  The >= 2 threshold preserves the ability to complete the
 *      three-way NTLM handshake (Type-1/Type-2/Type-3) on a single TCP
 *      connection: c->requests == 1 when the Type-3 message arrives.
 *
 * ── Configuration directives (upstream context) ────────────────────────────
 *
 *   ntlm [connections]     max cached upstream connections (default: 100)
 *   ntlm_timeout timeout   idle-connection timeout          (default: 60s)
 *   ntlm_time time         max wall-clock connection age    (default: 1h)
 *   ntlm_requests number   max requests per connection      (default: 1000)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* ── Forward declarations ─────────────────────────────────────────────────── */

static ngx_int_t ngx_http_upstream_init_ntlm(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_init_ntlm_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ntlm_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_ntlm_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_close(ngx_connection_t *c);
static void ngx_http_upstream_ntlm_notify_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void *ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_ntlm_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_upstream_ntlm_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_http_upstream_client_conn_cleanup(void *data);

/* ── Data structures ─────────────────────────────────────────────────────── */

typedef struct {
    ngx_uint_t                          max_cached;
    ngx_uint_t                          max_requests;
    ngx_msec_t                          time;
    ngx_msec_t                          timeout;
    ngx_queue_t                         free;
    ngx_queue_t                         cache;
    ngx_http_upstream_init_pt           original_init_upstream;
    ngx_http_upstream_init_peer_pt      original_init_peer;
} ngx_http_upstream_ntlm_srv_conf_t;

typedef struct {
    ngx_http_upstream_ntlm_srv_conf_t  *conf;
    ngx_queue_t                         queue;
    ngx_connection_t                   *peer_connection;
    ngx_connection_t                   *client_connection;
    /*
     * in_cache is the authoritative ownership indicator (invariant I1).
     * All releases MUST go through ngx_http_upstream_ntlm_item_release().
     */
    unsigned                            in_cache:1;
} ngx_http_upstream_ntlm_cache_t;

typedef struct {
    ngx_http_upstream_ntlm_srv_conf_t  *conf;
    ngx_http_upstream_t                *upstream;
    void                               *data;
    ngx_connection_t                   *client_connection;
    unsigned                            cached:1;
    unsigned                            ntlm_init:1;
    ngx_event_get_peer_pt               original_get_peer;
    ngx_event_free_peer_pt              original_free_peer;
    ngx_event_notify_peer_pt            original_notify;
#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt       original_set_session;
    ngx_event_save_peer_session_pt      original_save_session;
#endif
} ngx_http_upstream_ntlm_peer_data_t;

/* ── Module registration ─────────────────────────────────────────────────── */

static ngx_command_t ngx_http_upstream_ntlm_commands[] = {

    { ngx_string("ntlm"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_upstream_ntlm_directive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ntlm_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_ntlm_srv_conf_t, timeout),
      NULL },

    { ngx_string("ntlm_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_ntlm_srv_conf_t, time),
      NULL },

    { ngx_string("ntlm_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_ntlm_srv_conf_t, max_requests),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_ntlm_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    NULL,                                   /* create main configuration */
    ngx_http_upstream_ntlm_init_main_conf,  /* init main configuration */
    ngx_http_upstream_ntlm_create_conf,     /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};

ngx_module_t ngx_http_upstream_ntlm_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ntlm_ctx,
    ngx_http_upstream_ntlm_commands,
    NGX_HTTP_MODULE,
    NULL,   /* init master */
    NULL,   /* init module */
    NULL,   /* init process */
    NULL,   /* init thread */
    NULL,   /* exit thread */
    NULL,   /* exit process */
    NULL,   /* exit master */
    NGX_MODULE_V1_PADDING
};

/* ── Helper: release a cache item back to the free list ─────────────────── */

/*
 * ngx_http_upstream_ntlm_item_release — single, canonical release path.
 *
 * Atomically clears all three ownership fields (in_cache, peer_connection,
 * client_connection) before touching any queue, satisfying invariant I1.
 * Callers are responsible for closing peer_connection if needed; this
 * function only manages the item's queue state.
 */
static ngx_inline void
ngx_http_upstream_ntlm_item_release(ngx_http_upstream_ntlm_cache_t *item)
{
    item->in_cache = 0;
    item->peer_connection = NULL;
    item->client_connection = NULL;
    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&item->conf->free, &item->queue);
}

/* ── Upstream initialisation ─────────────────────────────────────────────── */

static ngx_int_t
ngx_http_upstream_init_ntlm(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                          i;
    ngx_http_upstream_ntlm_cache_t     *cached;
    ngx_http_upstream_ntlm_srv_conf_t  *hncf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ntlm init");

    hncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    ngx_conf_init_uint_value(hncf->max_cached, 100);
    ngx_conf_init_msec_value(hncf->timeout, 60000);
    ngx_conf_init_uint_value(hncf->max_requests, 1000);
    ngx_conf_init_msec_value(hncf->time, 3600000);

    if (hncf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Do not wrap us->peer.init here.  Wrapping is deferred to
     * ngx_http_upstream_ntlm_init_main_conf so that the NTLM layer is always
     * installed after any peer wrappers that other modules inject in their own
     * init_main_conf hooks (e.g. nginx master's automatic keepalive injection),
     * keeping NTLM as the outermost wrapper regardless of nginx version.
     */

    cached = ngx_pcalloc(cf->pool,
                         sizeof(ngx_http_upstream_ntlm_cache_t)
                         * hncf->max_cached);
    if (cached == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&hncf->cache);
    ngx_queue_init(&hncf->free);

    for (i = 0; i < hncf->max_cached; i++) {
        ngx_queue_insert_head(&hncf->free, &cached[i].queue);
        cached[i].conf = hncf;
    }

    return NGX_OK;
}

/* ── Per-request peer initialisation ────────────────────────────────────── */

static ngx_int_t
ngx_http_upstream_init_ntlm_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_ntlm_peer_data_t  *hnpd;
    ngx_http_upstream_ntlm_srv_conf_t   *hncf;
    ngx_str_t                            auth;

    hncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    hnpd = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ntlm_peer_data_t));
    if (hnpd == NULL) {
        return NGX_ERROR;
    }

    if (hncf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    hnpd->ntlm_init = 0;
    hnpd->cached    = 0;

    if (r->headers_in.authorization != NULL) {
        auth = r->headers_in.authorization->value;

        if ((auth.len >= sizeof("NTLM") - 1
             && ngx_strncasecmp(auth.data, (u_char *) "NTLM",
                                sizeof("NTLM") - 1) == 0
             && (auth.len == sizeof("NTLM") - 1
                 || auth.data[sizeof("NTLM") - 1] == ' '))
            || (auth.len >= sizeof("Negotiate") - 1
                && ngx_strncasecmp(auth.data, (u_char *) "Negotiate",
                                   sizeof("Negotiate") - 1) == 0
                && (auth.len == sizeof("Negotiate") - 1
                    || auth.data[sizeof("Negotiate") - 1] == ' ')))
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ntlm: authorization header detected");
            hnpd->ntlm_init = 1;
        }
    }

    hnpd->conf              = hncf;
    hnpd->upstream          = r->upstream;
    hnpd->data              = r->upstream->peer.data;
    hnpd->client_connection = r->connection;

    hnpd->original_get_peer  = r->upstream->peer.get;
    hnpd->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = hnpd;
    r->upstream->peer.get  = ngx_http_upstream_get_ntlm_peer;
    r->upstream->peer.free = ngx_http_upstream_free_ntlm_peer;

    hnpd->original_notify = NULL;
    if (r->upstream->peer.notify) {
        hnpd->original_notify      = r->upstream->peer.notify;
        r->upstream->peer.notify   = ngx_http_upstream_ntlm_notify_peer;
    }

#if (NGX_HTTP_SSL)
    hnpd->original_set_session  = r->upstream->peer.set_session;
    hnpd->original_save_session = r->upstream->peer.save_session;

    r->upstream->peer.set_session  = ngx_http_upstream_ntlm_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_ntlm_save_session;
#endif

    return NGX_OK;
}

/* ── get peer: select (or reuse) an upstream connection ─────────────────── */

static ngx_int_t
ngx_http_upstream_get_ntlm_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t  *hndp = data;
    ngx_http_upstream_ntlm_cache_t      *item;
    ngx_int_t                            rc;
    ngx_queue_t                         *q, *cache;
    ngx_connection_t                    *c;

    rc = hndp->original_get_peer(pc, hndp->data);
    if (rc != NGX_OK) {
        return rc;
    }

    cache = &hndp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);

        if (item->client_connection != hndp->client_connection) {
            continue;
        }

        c = item->peer_connection;

        /*
         * Invariant I4 — stale-credential eviction.
         *
         * If new NTLM/Negotiate credentials arrived and the upstream TCP
         * connection has already completed its handshake (c->requests >= 2),
         * close the old authenticated session so that the new identity gets a
         * fresh upstream connection.  The >= 2 threshold preserves the ability
         * to send the NTLM Type-3 message on the same TCP connection as
         * Type-1 (c->requests == 1 at that point).
         */
        if (hndp->ntlm_init && c->requests >= 2) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "ntlm: new credentials on established session, "
                           "evicting upstream connection %p (requests=%ui)",
                           c, c->requests);
            ngx_http_upstream_ntlm_item_release(item);
            ngx_http_upstream_ntlm_close(c);
            break; /* fall through → NGX_OK → fresh upstream connection */
        }

        /*
         * Reuse the cached connection.  Release through the canonical helper
         * so ownership fields and queue movement stay atomic and consistent
         * (invariant I1).
         */
        ngx_http_upstream_ntlm_item_release(item);

        hndp->cached = 1;
        goto found;
    }

    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "ntlm: reusing upstream connection %p", c);

    c->idle   = 0;
    c->sent   = 0;

    /*
     * Restore c->read->data to the connection pointer (invariant I2).
     * While cached, c->read->data held the NTLM cache item so that our
     * close_handler could retrieve it without touching c->data.
     * nginx upstream core requires ev->data == c, so reset before reuse.
     */
    c->read->data = c;
    c->data       = NULL;
    c->log        = pc->log;
    c->read->log  = pc->log;
    c->write->log = pc->log;
    c->pool->log  = pc->log;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}

/* ── free peer: decide whether to cache the upstream connection ──────────── */

/*
 * Fault-injection for testing the OOM guard (invariant I3).
 * Build nginx with -DNGX_NTLM_TEST_CLEANUP_NULL to make
 * ngx_pool_cleanup_add() always return NULL inside this translation unit,
 * exercising the "not caching upstream connection" error path.
 * See t/001-sanity.t TEST 6 for the corresponding test.
 */
#ifdef NGX_NTLM_TEST_CLEANUP_NULL
#  undef  ngx_pool_cleanup_add
#  define ngx_pool_cleanup_add(pool, size)  NULL
#endif

static void
ngx_http_upstream_free_ntlm_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_ntlm_peer_data_t  *hndp = data;
    ngx_http_upstream_ntlm_cache_t      *item;
    ngx_queue_t                         *q;
    ngx_connection_t                    *c;
    ngx_http_upstream_t                 *u;
    ngx_pool_cleanup_t                  *cln;
    ngx_http_upstream_ntlm_cache_t      *cleanup_item;

    u = hndp->upstream;
    c = pc->connection;

    /* Reject connections that cannot safely be reused. */

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (!u->request_body_sent) {
        goto invalid;
    }

    if (ngx_terminate || ngx_exiting) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    if (c->requests >= hndp->conf->max_requests) {
        goto invalid;
    }

    if (ngx_current_msec - c->start_time > hndp->conf->time) {
        goto invalid;
    }

    /* Only cache connections that were part of an NTLM session. */
    if (hndp->ntlm_init == 0 && hndp->cached == 0) {
        goto invalid;
    }

    /* Acquire a free slot, evicting the oldest entry if the cache is full. */

    if (ngx_queue_empty(&hndp->conf->free)) {
        ngx_connection_t *old_c;

        /*
         * Cache is full.  Evict the oldest (tail) entry through the canonical
         * release path, then reuse the resulting free slot.
         */
        q    = ngx_queue_last(&hndp->conf->cache);
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);

        old_c = item->peer_connection;

        ngx_http_upstream_ntlm_item_release(item);

        q    = ngx_queue_head(&hndp->conf->free);
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);
        ngx_queue_remove(q);

        if (old_c != NULL) {
            ngx_http_upstream_ntlm_close(old_c);
        }
    } else {
        q    = ngx_queue_head(&hndp->conf->free);
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);
        ngx_queue_remove(q);
    }

    ngx_queue_insert_head(&hndp->conf->cache, q);

    item->peer_connection   = c;
    item->client_connection = hndp->client_connection;
    item->in_cache          = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "ntlm: caching upstream connection %p for client %p",
                   c, item->client_connection);

    /*
     * Invariant I3 — OOM guard.
     *
     * Register a cleanup handler on the client connection pool so that the
     * upstream connection is closed when the client disconnects.  If the pool
     * allocator fails, undo the cache insertion: without a cleanup handler the
     * item would hold a client_connection pointer that nginx may recycle for a
     * different client, enabling a session-hijack via pointer reuse (ABA).
     *
     * If the client connection already has a handler from a previous request,
     * update its data pointer to the current item instead of registering a
     * second handler.
     */
    cleanup_item = NULL;
    for (cln = item->client_connection->pool->cleanup;
         cln != NULL;
         cln = cln->next)
    {
        if (cln->handler == ngx_http_upstream_client_conn_cleanup) {
            cln->data    = item;
            cleanup_item = item;
            break;
        }
    }

    if (cleanup_item == NULL) {
        cln = ngx_pool_cleanup_add(item->client_connection->pool, 0);
        if (cln == NULL) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                          "ntlm: failed to allocate cleanup handler,"
                          " not caching upstream connection");
            /*
             * Undo the cache insertion (invariant I3): clear all ownership
             * fields and return the slot to the free list.
             */
            ngx_http_upstream_ntlm_item_release(item);
            goto invalid;
        }
        cln->handler = ngx_http_upstream_client_conn_cleanup;
        cln->data    = item;
    }

    pc->connection    = NULL;
    c->read->delayed  = 0;

    ngx_add_timer(c->read, hndp->conf->timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_upstream_ntlm_dummy_handler;
    c->read->handler  = ngx_http_upstream_ntlm_close_handler;

    /*
     * Invariant I2 — store the cache item in c->read->data, not c->data.
     *
     * nginx's ngx_http_upstream_handler() requires c->data to be the request
     * pointer; overwriting it with a cache item pointer causes a segfault on
     * nginx >= 1.25 if any posted or ready event reaches that handler while
     * the connection is idle.  Because we have replaced c->read->handler with
     * our own close_handler, only our handler runs on read events; it
     * retrieves the item via ev->data (== c->read->data) without touching
     * c->data.  c->read->data is restored to c when the connection is handed
     * back to upstream core (see ngx_http_upstream_get_ntlm_peer).
     */
    c->read->data = item;
    c->data       = NULL;
    c->idle       = 1;
    c->log        = ngx_cycle->log;
    c->read->log  = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log  = ngx_cycle->log;

    if (c->read->ready) {
        ngx_http_upstream_ntlm_close_handler(c->read);
    }

    /*
     * Call original_free_peer to release round-robin (and any other lower
     * layer) accounting — e.g. decrementing the round-robin peer's conns
     * counter.  pc->connection is already NULL so keepalive's free_peer
     * (if present) will skip its own caching and delegate to round-robin.
     */
    hndp->original_free_peer(pc, hndp->data, state);
    return;

invalid:
    hndp->original_free_peer(pc, hndp->data, state);
}

/* ── Client-connection pool cleanup handler ─────────────────────────────── */

/*
 * Called when the client connection's pool is destroyed (i.e. the client
 * disconnects).  Closes the bound upstream connection synchronously so that
 * the item is immediately returned to the free list.  Must NOT post an event:
 * a posted event fires asynchronously and by that time the upstream connection
 * may have been claimed for a new request, causing a double-close or queue
 * corruption.
 */
static void
ngx_http_upstream_client_conn_cleanup(void *data)
{
    ngx_http_upstream_ntlm_cache_t  *item = data;
    ngx_connection_t                *c;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "ntlm: client connection closed %p, dropping upstream %p",
                   item->client_connection, item->peer_connection);

    /*
     * Guard against double-execution (invariant I1).  in_cache == 0 means
     * the connection was already consumed by get_ntlm_peer or closed by
     * the close_handler / an eviction.  Nothing to do.
     */
    if (!item->in_cache) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "ntlm: upstream already released for client %p/%p",
                       item->client_connection, item->peer_connection);
        return;
    }

    c = item->peer_connection;

    /* Release the item atomically (invariant I1) before any queue or I/O. */
    ngx_http_upstream_ntlm_item_release(item);

    if (c == NULL) {
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ngx_http_upstream_ntlm_close(c);
}

/* ── Idle-connection event handlers ─────────────────────────────────────── */

static void
ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ntlm: dummy handler");
}

static void
ngx_http_upstream_ntlm_notify_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_upstream_ntlm_peer_data_t  *hndp = data;

    if (hndp->original_notify) {
        hndp->original_notify(pc, hndp->data, type);
    }
}

/*
 * ngx_http_upstream_ntlm_close_handler — fires on read activity or timeout
 * for an idle cached upstream connection.
 *
 * ev->data holds the owning cache item (invariant I2: stored in c->read->data,
 * not c->data).  We close the upstream TCP connection and return the slot to
 * the free list.
 */
static void
ngx_http_upstream_ntlm_close_handler(ngx_event_t *ev)
{
    ngx_http_upstream_ntlm_cache_t  *item;
    ngx_connection_t                *c;
    int                              n;
    char                             buf[1];

    /*
     * Retrieve the cache item from the read-event's data field (invariant I2).
     * c->data is not touched; nginx core expects it to hold the request pointer.
     */
    item = ev->data;

    if (item == NULL || !item->in_cache) {
        /* Already released by cleanup or eviction. */
        return;
    }

    c = item->peer_connection;

    if (c == NULL) {
        /* Ownership was cleared by a concurrent path. */
        return;
    }

    if (c->close || c->read->timedout) {
        goto close;
    }

    if (c->fd == (ngx_socket_t) -1) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        /* Spurious wake-up: upstream is still idle. */
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

    /* n == 0 (EOF), n > 0 (unexpected data), or a real error. */

close:

    /*
     * Double-check ownership before closing (belt-and-suspenders for I1).
     * A concurrent cleanup or eviction may have cleared in_cache since the
     * checks above.
     */
    if (!item->in_cache || item->peer_connection != c) {
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "ntlm: closing idle upstream %p (timedout=%u, recv=%i)",
                   c, c->read->timedout, n);

    /* Release atomically (invariant I1) before any queue or I/O. */
    ngx_http_upstream_ntlm_item_release(item);

    ngx_http_upstream_ntlm_close(c);
}

/* ── Connection teardown ─────────────────────────────────────────────────── */

static void
ngx_http_upstream_ntlm_close(ngx_connection_t *c)
{
#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_ntlm_close;
            return;
        }
    }
#endif

    ngx_pool_t *pool = c->pool;
    c->pool = NULL;
    ngx_close_connection(c);
    if (pool) {
        ngx_destroy_pool(pool);
    }
}

/* ── SSL session pass-through ────────────────────────────────────────────── */

#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t  *hndp = data;

    return hndp->original_set_session(pc, hndp->data);
}

static void
ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t  *hndp = data;

    hndp->original_save_session(pc, hndp->data);
}

#endif

/* ── Configuration ───────────────────────────────────────────────────────── */

/*
 * ngx_http_upstream_ntlm_init_main_conf — install the NTLM peer wrapper.
 *
 * Runs during nginx's init_main_conf phase, which executes all HTTP module
 * init_main_conf hooks in ascending module-index order.  Built-in modules
 * (including ngx_http_upstream_keepalive_module) have lower indices than
 * --add-module extensions, so this hook always runs AFTER the keepalive
 * module has had a chance to inject its own peer wrapper.
 *
 * nginx master introduced automatic keepalive injection in keepalive's
 * init_main_conf.  If NTLM wrapped peer.init during init_upstream (as it did
 * before this fix), the keepalive wrapper would sit on the outside, stealing
 * connections before NTLM could pin them and breaking NTLM session stickiness.
 * Moving the wrapping here guarantees NTLM is always the outermost layer.
 */
static char *
ngx_http_upstream_ntlm_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                           i;
    ngx_http_upstream_main_conf_t       *umcf;
    ngx_http_upstream_srv_conf_t       **uscfp;
    ngx_http_upstream_ntlm_srv_conf_t   *hncf;

    umcf  = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        /* skip implicit upstreams (no server-conf block) */
        if (uscfp[i]->srv_conf == NULL) {
            continue;
        }

        hncf = ngx_http_conf_upstream_srv_conf(uscfp[i],
                                               ngx_http_upstream_ntlm_module);

        /* skip upstreams that don't have the ntlm directive */
        if (hncf->original_init_upstream == NULL) {
            continue;
        }

        /*
         * At this point uscfp[i]->peer.init points to whatever the last
         * init_main_conf hook installed (round-robin, keepalive wrapper, etc.).
         * Save it as our original and replace it with the NTLM wrapper.
         */
        hncf->original_init_peer = uscfp[i]->peer.init;
        uscfp[i]->peer.init      = ngx_http_upstream_init_ntlm_peer;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_ntlm_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ntlm_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->max_cached  = NGX_CONF_UNSET_UINT;
    conf->max_requests = NGX_CONF_UNSET_UINT;
    conf->time        = NGX_CONF_UNSET_MSEC;
    conf->timeout     = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_http_upstream_ntlm_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_upstream_srv_conf_t       *uscf;
    ngx_http_upstream_ntlm_srv_conf_t  *hncf = conf;
    ngx_str_t                          *value;
    ngx_int_t                           n;

    if (cf->args->nelts == 2) {
        value = cf->args->elts;
        n = ngx_atoi(value[1].data, value[1].len);
        if (n == NGX_ERROR || n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ntlm: invalid value \"%V\" in \"%V\" directive",
                               &value[1], &cmd->name);
            return NGX_CONF_ERROR;
        }
        hncf->max_cached = (ngx_uint_t) n;
    }

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    hncf->original_init_upstream = uscf->peer.init_upstream
                                   ? uscf->peer.init_upstream
                                   : ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_upstream_init_ntlm;

    return NGX_CONF_OK;
}
