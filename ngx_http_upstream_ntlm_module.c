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
 *      is not awaiting a continuation of that authentication scheme, the old
 *      session is evicted and closed.  A new NTLM Type-1 or SPNEGO initial
 *      token always starts a fresh session.  Response status alone never
 *      determines whether negotiation has completed.
 *
 *  I5. Cached sessions belong to a client connection pointer AND number.
 *      Client-pool cleanup tracks this owner separately for each upstream
 *      configuration, never a reusable cache slot, and releases every entry
 *      belonging to the owner.
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

typedef enum {
    NGX_NTLM_AUTH_NONE,
    NGX_NTLM_AUTH_NTLM,
    NGX_NTLM_AUTH_NEGOTIATE
} ngx_http_upstream_ntlm_auth_scheme_t;

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
    ngx_atomic_uint_t                   client_connection_number;
    /*
     * in_cache is the authoritative ownership indicator (invariant I1).
     * All releases MUST go through ngx_http_upstream_ntlm_item_release().
     */
    unsigned                            in_cache:1;
    ngx_http_upstream_ntlm_auth_scheme_t auth_scheme;
    unsigned                            awaiting_token:1;
} ngx_http_upstream_ntlm_cache_t;

typedef struct {
    ngx_http_upstream_ntlm_srv_conf_t  *conf;
    ngx_connection_t                   *client_connection;
    ngx_atomic_uint_t                   client_connection_number;
} ngx_http_upstream_ntlm_cleanup_t;

typedef struct {
    ngx_http_upstream_ntlm_srv_conf_t  *conf;
    ngx_http_upstream_t                *upstream;
    ngx_pool_t                         *pool;
    void                               *data;
    ngx_connection_t                   *client_connection;
    unsigned                            cached:1;
    unsigned                            ntlm_init:1;
    unsigned                            can_continue:1;
    unsigned                            awaiting_token:1;
    ngx_http_upstream_ntlm_auth_scheme_t auth_scheme;
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
 * Clears the ownership flag, connection pointers, and client connection number
 * before touching any queue, satisfying invariant I1.
 * Callers are responsible for closing peer_connection if needed; this
 * function only manages the item's queue state.
 */
static ngx_inline void
ngx_http_upstream_ntlm_item_release(ngx_http_upstream_ntlm_cache_t *item)
{
    item->in_cache = 0;
    item->peer_connection = NULL;
    item->client_connection = NULL;
    item->client_connection_number = 0;
    item->auth_scheme = NGX_NTLM_AUTH_NONE;
    item->awaiting_token = 0;
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

/* ── Authentication exchange tracking ──────────────────────────────────── */

static ngx_int_t
ngx_http_upstream_ntlm_auth_token(ngx_http_request_t *r,
    ngx_http_upstream_ntlm_peer_data_t *hnpd, ngx_str_t *auth)
{
    ngx_str_t  encoded, decoded;
    size_t     scheme_len;

    scheme_len = hnpd->auth_scheme == NGX_NTLM_AUTH_NTLM
                 ? sizeof("NTLM") - 1 : sizeof("Negotiate") - 1;
    encoded.data = auth->data + scheme_len;
    encoded.len = auth->len - scheme_len;
    while (encoded.len && encoded.data[0] == ' ') {
        encoded.data++;
        encoded.len--;
    }

    if (encoded.len == 0) {
        return NGX_OK;
    }

    decoded.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(encoded.len));
    if (decoded.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&decoded, &encoded) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ntlm: invalid authentication token, not reusing session");
        return NGX_OK;
    }

    if (decoded.len >= 12
        && ngx_memcmp(decoded.data, "NTLMSSP\0", 8) == 0)
    {
        if (decoded.data[9] == 0 && decoded.data[10] == 0
            && decoded.data[11] == 0)
        {
            hnpd->awaiting_token = decoded.data[8] == 1;
            hnpd->can_continue = decoded.data[8] == 3;
        }
    } else if (hnpd->auth_scheme == NGX_NTLM_AUTH_NEGOTIATE && decoded.len) {
        /*
         * GSS InitialContextToken (application tag 0) starts a new exchange.
         * Only a NegTokenResp (context tag 1) can continue a SPNEGO exchange.
         * It still requires a matching upstream challenge on this connection.
         */
        hnpd->can_continue = decoded.data[0] == 0xa1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_ntlm_der_value(ngx_str_t *input, u_char tag, ngx_str_t *value)
{
    u_char  *p, *last;
    size_t   len, n;

    p = input->data;
    last = p + input->len;
    if (input->len < 2 || *p++ != tag) {
        return NGX_ERROR;
    }
    len = *p++;
    if (len & 0x80) {
        n = len & 0x7f;
        if (n == 0 || n > sizeof(size_t) || n > (size_t) (last - p)) {
            return NGX_ERROR;
        }
        len = 0;
        while (n--) {
            len = (len << 8) | *p++;
        }
    }
    if (len > (size_t) (last - p)) {
        return NGX_ERROR;
    }
    value->data = p;
    value->len = len;
    input->data = p + len;
    input->len = last - input->data;
    return NGX_OK;
}

static ngx_uint_t
ngx_http_upstream_ntlm_challenge_pending(ngx_str_t token)
{
    ngx_str_t  value, state;

    if (token.len == 0) {
        return 0;
    }
    if (token.data[0] != 0xa1) {
        return token.len >= 12
               && ngx_memcmp(token.data, "NTLMSSP\0\2\0\0\0", 12) == 0;
    }
    if (ngx_http_upstream_ntlm_der_value(&token, 0xa1, &value) != NGX_OK
        || token.len != 0
        || ngx_http_upstream_ntlm_der_value(&value, 0x30, &token) != NGX_OK
        || value.len != 0 || token.len == 0)
    {
        return 0;
    }
    if (token.data[0] != 0xa0) {
        return 1; /* negState is optional; the response token continues exchange. */
    }
    if (ngx_http_upstream_ntlm_der_value(&token, 0xa0, &value) != NGX_OK
        || ngx_http_upstream_ntlm_der_value(&value, 0x0a, &state) != NGX_OK
        || value.len != 0 || state.len != 1)
    {
        return 0;
    }
    /* accept-incomplete or request-mic, not accept-completed or reject. */
    return state.data[0] == 1 || state.data[0] == 3;
}

static ngx_int_t
ngx_http_upstream_ntlm_challenge_token(ngx_http_upstream_ntlm_peer_data_t *hndp,
    ngx_str_t value, ngx_str_t scheme)
{
    u_char  *p, *start, *last;
    ngx_str_t encoded, decoded;

    p = value.data;
    last = p + value.len;
    while (p < last) {
        while (p < last && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        start = p;
        if ((size_t) (last - p) > scheme.len
            && ngx_strncasecmp(p, scheme.data, scheme.len) == 0
            && (p[scheme.len] == ' ' || p[scheme.len] == '\t'))
        {
            p += scheme.len;
            while (p < last && (*p == ' ' || *p == '\t')) {
                p++;
            }
            if (p < last && *p != ',') {
                encoded.data = p;
                while (p < last && *p != ',' && *p != ' ' && *p != '\t') {
                    p++;
                }
                encoded.len = p - encoded.data;
                decoded.data = ngx_pnalloc(hndp->pool,
                                          ngx_base64_decoded_length(encoded.len));
                if (decoded.data == NULL) {
                    return NGX_ERROR;
                }
                if (ngx_decode_base64(&decoded, &encoded) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, hndp->client_connection->log, 0,
                                  "ntlm: invalid upstream authentication token");
                    return 0;
                }
                return ngx_http_upstream_ntlm_challenge_pending(decoded);
            }
        }
        p = start;
        while (p < last && *p != ',') {
            if (*p++ == '"') {
                while (p < last) {
                    if (*p == '\\' && p + 1 < last) {
                        p += 2;
                    } else if (*p++ == '"') {
                        break;
                    }
                }
            }
        }
    }

    return 0;
}

static ngx_int_t
ngx_http_upstream_ntlm_has_challenge(ngx_http_upstream_ntlm_peer_data_t *hndp)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_uint_t       i;
    ngx_int_t        pending;
    ngx_str_t        scheme;

    if (hndp->auth_scheme == NGX_NTLM_AUTH_NTLM) {
        ngx_str_set(&scheme, "NTLM");
    } else {
        ngx_str_set(&scheme, "Negotiate");
    }

    part = &hndp->upstream->headers_in.headers.part;
    header = part->elts;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        if (header[i].key.len != sizeof("WWW-Authenticate") - 1
            || ngx_strncasecmp(header[i].key.data,
                               (u_char *) "WWW-Authenticate",
                               sizeof("WWW-Authenticate") - 1) != 0)
        {
            continue;
        }
        pending = ngx_http_upstream_ntlm_challenge_token(hndp, header[i].value,
                                                        scheme);
        if (pending != 0) {
            return pending;
        }
    }

    return 0;
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

    if (r->http_version >= NGX_HTTP_VERSION_20) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ntlm: HTTP/2 and HTTP/3 requests are not supported for ntlm "
                      "upstreams");
        return NGX_ERROR;
    }

    hnpd = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ntlm_peer_data_t));
    if (hnpd == NULL) {
        return NGX_ERROR;
    }

    if (hncf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    hnpd->ntlm_init = 0;
    hnpd->cached    = 0;
    hnpd->auth_scheme = NGX_NTLM_AUTH_NONE;
    hnpd->can_continue = 0;
    hnpd->awaiting_token = 0;

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
            hnpd->auth_scheme =
                ngx_strncasecmp(auth.data, (u_char *) "NTLM", 4) == 0
                ? NGX_NTLM_AUTH_NTLM : NGX_NTLM_AUTH_NEGOTIATE;
            if (ngx_http_upstream_ntlm_auth_token(r, hnpd, &auth) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    hnpd->conf              = hncf;
    hnpd->upstream          = r->upstream;
    hnpd->pool              = r->pool;
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
    if (rc != NGX_OK && rc != NGX_DONE) {
        return rc;
    }

    cache = &hndp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);

        if (item->client_connection != hndp->client_connection
            || item->client_connection_number
               != hndp->client_connection->number)
        {
            continue;
        }

        c = item->peer_connection;
        if (c == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "ntlm: skipping stale cache entry for client %p",
                           item->client_connection);
            ngx_http_upstream_ntlm_item_release(item);
            continue;
        }

        if (ngx_current_msec - c->start_time > hndp->conf->time
            || (hndp->ntlm_init
                && (!hndp->can_continue || !item->awaiting_token
                    || hndp->auth_scheme != item->auth_scheme)))
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "ntlm: retiring expired or reauthenticated "
                           "upstream connection %p (requests=%ui)",
                           c, c->requests);
            ngx_http_upstream_ntlm_item_release(item);
            ngx_http_upstream_ntlm_close(c);
            break;
        }

        /*
         * Reuse the cached connection.  Release through the canonical helper
         * so ownership fields and queue movement stay atomic and consistent
         * (invariant I1).
         */
        if (!hndp->ntlm_init) {
            hndp->auth_scheme = item->auth_scheme;
            hndp->awaiting_token = item->awaiting_token;
        }
        ngx_http_upstream_ntlm_item_release(item);

        hndp->cached = 1;
        goto found;
    }

    return rc;

found:

    /*
     * Keep the balancer reservation, but discard an unrelated shared socket
     * selected by its keepalive wrapper in favor of the owner's pinned socket.
     */
    if (rc == NGX_DONE && pc->connection != NULL) {
        ngx_http_upstream_ntlm_close(pc->connection);
        pc->connection = NULL;
    }

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
    ngx_http_upstream_ntlm_cleanup_t    *cleanup;
    ngx_int_t                            awaiting_token;

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

    awaiting_token = ngx_http_upstream_ntlm_has_challenge(hndp);
    if (awaiting_token == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "ntlm: failed to allocate challenge tracking");
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
    item->client_connection_number = hndp->client_connection->number;
    item->in_cache          = 1;
    item->auth_scheme = hndp->auth_scheme;
    item->awaiting_token = hndp->awaiting_token
                           || awaiting_token;

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
     * Register once per client connection and upstream configuration.  Cleanup
     * tracks the owner, not a cache slot that may be reassigned to another
     * client, and releases every entry belonging to that owner.
     */
    cleanup = NULL;
    for (cln = item->client_connection->pool->cleanup;
         cln != NULL;
         cln = cln->next)
    {
        if (cln->handler == ngx_http_upstream_client_conn_cleanup) {
             cleanup = cln->data;
             if (cleanup->conf == hndp->conf
                 && cleanup->client_connection == item->client_connection
                 && cleanup->client_connection_number
                    == item->client_connection_number)
             {
                 break;
             }
             cleanup = NULL;
         }
    }

    if (cleanup == NULL) {
         cln = ngx_pool_cleanup_add(item->client_connection->pool,
                                   sizeof(ngx_http_upstream_ntlm_cleanup_t));
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
        cleanup = cln->data;
        cleanup->conf = hndp->conf;
        cleanup->client_connection = item->client_connection;
        cleanup->client_connection_number = item->client_connection_number;
        cln->handler = ngx_http_upstream_client_conn_cleanup;
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
invalid:
    /*
     * Rejected NTLM sessions must not enter a lower layer's shared cache.
     * Withhold the connection while releasing balancer accounting, then
     * restore it so upstream core closes it on finalization or retry.
     * Successful private caching has already cleared pc->connection.
     * Non-NTLM connections retain the lower layer's normal caching behavior.
     */
    c = NULL;
    if (hndp->ntlm_init || hndp->cached) {
        c = pc->connection;
        pc->connection = NULL;
    }

    hndp->original_free_peer(pc, hndp->data, state);

    if (c != NULL) {
        /* Caching is finished; restore the socket for core teardown, not reuse. */
        pc->connection = c;
    }

    return;
}

/* ── Client-connection pool cleanup handler ─────────────────────────────── */

/*
 * Called when the client connection's pool is destroyed (i.e. the client
 * disconnects).  Closes all of the owner's cached upstream connections
 * synchronously.  Must NOT post an event:
 * a posted event fires asynchronously and by that time the upstream connection
 * may have been claimed for a new request, causing a double-close or queue
 * corruption.
 */
static void
ngx_http_upstream_client_conn_cleanup(void *data)
{
    ngx_http_upstream_ntlm_cleanup_t  *cleanup = data;
    ngx_http_upstream_ntlm_cache_t    *item;
    ngx_queue_t                       *q, *next, *cache;
    ngx_connection_t                  *c;

    cache = &cleanup->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = next)
    {
        next = ngx_queue_next(q);
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);

        if (!item->in_cache
            || item->client_connection != cleanup->client_connection
            || item->client_connection_number
               != cleanup->client_connection_number)
        {
            continue;
        }

        c = item->peer_connection;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "ntlm: client connection closed %p, dropping upstream %p",
                       cleanup->client_connection, c);

        ngx_http_upstream_ntlm_item_release(item);

        if (c != NULL) {
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            ngx_http_upstream_ntlm_close(c);
        }
    }
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
    ngx_int_t                        n = 0;
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

    if (c->pool) {
        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }
    ngx_close_connection(c);
}

/* ── SSL session pass-through ────────────────────────────────────────────── */

#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t  *hndp = data;

    /*
     * SSL session callbacks apply to new TLS handshakes only.
     * Reused NTLM-cached upstream connections are already handshaken.
     */
    if (pc == NULL || pc->connection == NULL || pc->cached) {
        return NGX_OK;
    }

    if (hndp->original_set_session == NULL) {
        return NGX_OK;
    }

    return hndp->original_set_session(pc, hndp->data);
}

static void
ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t  *hndp = data;

    if (pc == NULL || pc->connection == NULL || pc->cached) {
        return;
    }

    if (hndp->original_save_session) {
        hndp->original_save_session(pc, hndp->data);
    }
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
