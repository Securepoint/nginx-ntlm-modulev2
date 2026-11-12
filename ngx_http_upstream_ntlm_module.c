/*
 * Connection-bound NTLM/Negotiate upstream sessions for nginx >= 1.25.
 *
 * A client-pool cleanup owns each idle session directly.  The upstream LRU
 * only bounds idle capacity; it never supplies reusable ownership records.
 * Active sockets belong to upstream core, idle sockets to their client owner.
 * Event data always remains the connection pointer.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_COMPAT && !NGX_HTTP_SSL)
#error "NTLM compatible modules require --with-http_ssl_module"
#endif

typedef enum {
    NGX_NTLM_NO_AUTH,
    NGX_NTLM_OTHER_AUTH,
    NGX_NTLM_AUTH,
    NGX_NTLM_NEGOTIATE
} ngx_http_ntlm_scheme_t;

typedef enum {
    NGX_NTLM_INVALID_TOKEN,
    NGX_NTLM_INITIAL_TOKEN,
    NGX_NTLM_RESPONSE_TOKEN,
    NGX_NTLM_CHALLENGE_TOKEN,
    NGX_NTLM_COMPLETE_TOKEN
} ngx_http_ntlm_token_t;

typedef struct {
    ngx_uint_t                         max_cached;
    ngx_uint_t                         max_requests;
    ngx_msec_t                         time;
    ngx_msec_t                         timeout;
    ngx_uint_t                         cached;
    ngx_queue_t                        cache;
    ngx_http_upstream_init_peer_pt     original_init_peer;
    unsigned                          enabled:1;
} ngx_http_ntlm_conf_t;

typedef struct {
    ngx_addr_t                        *peer;
    ngx_http_ntlm_scheme_t             scheme;
    unsigned                          pending:1;
} ngx_http_ntlm_session_t;

typedef struct {
    ngx_http_ntlm_conf_t               *conf;
    ngx_http_upstream_conf_t           *tag;
    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;
    ngx_http_ntlm_session_t            *session;
} ngx_http_ntlm_owner_t;

typedef struct {
    ngx_http_request_t                 *request;
    ngx_http_ntlm_conf_t               *conf;
    ngx_http_ntlm_owner_t              *owner;
    ngx_http_ntlm_session_t            *session;
    ngx_http_ntlm_scheme_t              scheme;
    ngx_http_ntlm_token_t               token;
    unsigned                           reused:1;
    void                              *data;
    ngx_event_get_peer_pt              get;
    ngx_event_free_peer_pt             free;
    ngx_event_notify_peer_pt           notify;
#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      set_session;
    ngx_event_save_peer_session_pt     save_session;
#endif
} ngx_http_ntlm_peer_t;

static ngx_int_t ngx_http_ntlm_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_ntlm_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_ntlm_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
static void ngx_http_ntlm_notify(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type);
static void ngx_http_ntlm_cleanup(void *data);
static void ngx_http_ntlm_idle(ngx_event_t *ev);
static void ngx_http_ntlm_dummy(ngx_event_t *ev);
static void ngx_http_ntlm_close(ngx_connection_t *c);
static void *ngx_http_ntlm_create_conf(ngx_conf_t *cf);
static char *ngx_http_ntlm_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_ntlm_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_ntlm_set_session(ngx_peer_connection_t *pc, void *data);
static void ngx_http_ntlm_save_session(ngx_peer_connection_t *pc, void *data);
#endif

static ngx_command_t ngx_http_ntlm_commands[] = {
    { ngx_string("ntlm"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_ntlm_directive, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
    { ngx_string("ntlm_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET, offsetof(ngx_http_ntlm_conf_t, timeout), NULL },
    { ngx_string("ntlm_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET, offsetof(ngx_http_ntlm_conf_t, time), NULL },
    { ngx_string("ntlm_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1, ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET, offsetof(ngx_http_ntlm_conf_t, max_requests),
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_ntlm_ctx = {
    NULL, NULL, NULL, ngx_http_ntlm_init_main_conf,
    ngx_http_ntlm_create_conf, NULL, NULL, NULL
};

ngx_module_t ngx_http_upstream_ntlm_module = {
    NGX_MODULE_V1,
    &ngx_http_ntlm_ctx,
    ngx_http_ntlm_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_connection_t *
ngx_http_ntlm_detach(ngx_http_ntlm_owner_t *owner)
{
    ngx_connection_t  *c;

    c = owner->connection;
    if (c != NULL) {
        owner->connection = NULL;
        owner->session = NULL;
        ngx_queue_remove(&owner->queue);
        owner->conf->cached--;
        c->data = NULL;
    }

    return c;
}

static void
ngx_http_ntlm_cleanup(void *data)
{
    ngx_connection_t  *c;

    c = ngx_http_ntlm_detach(data);
    if (c != NULL) {
        ngx_http_ntlm_close(c);
    }
}

static ngx_http_ntlm_owner_t *
ngx_http_ntlm_find_owner(ngx_http_request_t *r, ngx_http_ntlm_conf_t *conf)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_ntlm_owner_t  *owner;

    for (cln = r->connection->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler != ngx_http_ntlm_cleanup) {
            continue;
        }
        owner = cln->data;
        if (owner->conf == conf && owner->tag == r->upstream->conf) {
            return owner;
        }
    }

    return NULL;
}

static ngx_addr_t *
ngx_http_ntlm_copy_peer(ngx_pool_t *pool, ngx_addr_t *source)
{
    ngx_addr_t  *peer;

    peer = ngx_palloc(pool, sizeof(ngx_addr_t) + source->socklen
                           + source->name.len);
    if (peer == NULL) {
        return NULL;
    }
    peer->sockaddr = (struct sockaddr *) (peer + 1);
    peer->socklen = source->socklen;
    ngx_memcpy(peer->sockaddr, source->sockaddr, source->socklen);
    peer->name.data = (u_char *) peer->sockaddr + source->socklen;
    peer->name.len = source->name.len;
    ngx_memcpy(peer->name.data, source->name.data, source->name.len);
    return peer;
}

static ngx_int_t
ngx_http_ntlm_der(ngx_str_t *input, u_char tag, ngx_str_t *value)
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
        if (n == 0 || n > sizeof(size_t) || n > (size_t) (last - p)
            || *p == 0)
        {
            return NGX_ERROR;
        }
        len = 0;
        while (n--) {
            len = (len << 8) | *p++;
        }
        if (len < 128) {
            return NGX_ERROR;
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

/*
 * SPNEGO payloads stay opaque.  Validate only the NegTokenResp envelope and
 * negotiation state; a leading 0xa1 byte alone is not a continuation token.
 */
static ngx_http_ntlm_token_t
ngx_http_ntlm_spnego(ngx_str_t token, ngx_uint_t challenge)
{
    ngx_str_t   sequence, field, value;
    ngx_uint_t  state, payload, previous, tag;
    u_char      inner;

    if (ngx_http_ntlm_der(&token, 0xa1, &field) != NGX_OK || token.len
        || ngx_http_ntlm_der(&field, 0x30, &sequence) != NGX_OK || field.len)
    {
        return NGX_NTLM_INVALID_TOKEN;
    }

    state = 4;
    payload = 0;
    previous = 0;
    while (sequence.len) {
        tag = sequence.data[0];
        if (tag < 0xa0 || tag > 0xa3 || tag <= previous
            || ngx_http_ntlm_der(&sequence, (u_char) tag, &field) != NGX_OK)
        {
            return NGX_NTLM_INVALID_TOKEN;
        }
        previous = tag;
        inner = tag == 0xa0 ? 0x0a : tag == 0xa1 ? 0x06 : 0x04;
        if (ngx_http_ntlm_der(&field, inner, &value) != NGX_OK
            || field.len || value.len == 0)
        {
            return NGX_NTLM_INVALID_TOKEN;
        }
        if (tag == 0xa0) {
            if (value.len != 1 || value.data[0] > 3) {
                return NGX_NTLM_INVALID_TOKEN;
            }
            state = value.data[0];
        } else if (tag >= 0xa2) {
            payload = 1;
        }
    }

    if (!challenge) {
        return payload ? NGX_NTLM_RESPONSE_TOKEN : NGX_NTLM_INVALID_TOKEN;
    }
    if (state == 0 || state == 2) {
        return NGX_NTLM_COMPLETE_TOKEN;
    }
    return state == 1 || state == 3 || payload
           ? NGX_NTLM_CHALLENGE_TOKEN : NGX_NTLM_INVALID_TOKEN;
}

static ngx_int_t
ngx_http_ntlm_decode(ngx_http_request_t *r, ngx_str_t encoded,
    ngx_http_ntlm_scheme_t scheme, ngx_uint_t challenge)
{
    ngx_str_t  token;

    token.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(encoded.len));
    if (token.data == NULL) {
        return NGX_ERROR;
    }
    if (encoded.len == 0 || ngx_decode_base64(&token, &encoded) != NGX_OK) {
        return NGX_NTLM_INVALID_TOKEN;
    }
    if (token.len >= 12 && ngx_memcmp(token.data, "NTLMSSP\0", 8) == 0) {
        if (token.data[9] || token.data[10] || token.data[11]) {
            return NGX_NTLM_INVALID_TOKEN;
        }
        switch (token.data[8]) {
        case 1:
            return challenge ? NGX_NTLM_INVALID_TOKEN : NGX_NTLM_INITIAL_TOKEN;
        case 2:
            return challenge ? NGX_NTLM_CHALLENGE_TOKEN : NGX_NTLM_INVALID_TOKEN;
        case 3:
            return challenge ? NGX_NTLM_INVALID_TOKEN : NGX_NTLM_RESPONSE_TOKEN;
        default:
            return NGX_NTLM_INVALID_TOKEN;
        }
    }
    if (scheme == NGX_NTLM_NEGOTIATE && token.len) {
        if (!challenge && token.data[0] == 0x60) {
            return NGX_NTLM_INITIAL_TOKEN;
        }
        return ngx_http_ntlm_spnego(token, challenge);
    }
    return NGX_NTLM_INVALID_TOKEN;
}

static ngx_http_ntlm_scheme_t
ngx_http_ntlm_scheme(ngx_str_t *value)
{
    ngx_str_t  name;

    name = *value;
    while (value->len && value->data[0] != ' ' && value->data[0] != '\t') {
        value->data++;
        value->len--;
    }
    name.len -= value->len;
    while (value->len && (value->data[0] == ' ' || value->data[0] == '\t')) {
        value->data++;
        value->len--;
    }
    if (name.len == 4 && ngx_strncasecmp(name.data, (u_char *) "NTLM", 4) == 0) {
        return NGX_NTLM_AUTH;
    }
    if (name.len == 9
        && ngx_strncasecmp(name.data, (u_char *) "Negotiate", 9) == 0)
    {
        return NGX_NTLM_NEGOTIATE;
    }
    return NGX_NTLM_OTHER_AUTH;
}

static ngx_int_t
ngx_http_ntlm_challenge(ngx_http_ntlm_peer_t *pd)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_str_t        value, entry;
    ngx_uint_t       i, quoted, seen;
    ngx_int_t        token;
    u_char          *p, *start, *last;

    part = &pd->request->upstream->headers_in.headers.part;
    header = part->elts;
    seen = 0;
    for (i = 0; /* void */; i++) {
        if (i == part->nelts) {
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
        seen = 1;
        value = header[i].value;
        p = value.data;
        last = p + value.len;
        while (p < last) {
            while (p < last && (*p == ',' || *p == ' ' || *p == '\t')) {
                p++;
            }
            start = p;
            quoted = 0;
            while (p < last) {
                if (*p == '\\' && quoted && p + 1 < last) {
                    p += 2;
                    continue;
                }
                if (*p == '"') {
                    quoted = !quoted;
                } else if (*p == ',' && !quoted) {
                    break;
                }
                p++;
            }
            entry.data = start;
            entry.len = p - start;
            if (ngx_http_ntlm_scheme(&entry) != pd->session->scheme) {
                continue;
            }
            while (entry.len && (entry.data[entry.len - 1] == ' '
                                || entry.data[entry.len - 1] == '\t'))
            {
                entry.len--;
            }
            token = ngx_http_ntlm_decode(pd->request, entry,
                                        pd->session->scheme, 1);
            if (token == NGX_ERROR) {
                return NGX_ERROR;
            }
            return token == NGX_NTLM_CHALLENGE_TOKEN;
        }
    }
    return seen ? 0 : NGX_DECLINED;
}

static ngx_int_t
ngx_http_ntlm_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_ntlm_peer_t  *pd;
    ngx_str_t             auth;
    ngx_int_t             token;

    if (r->http_version >= NGX_HTTP_VERSION_20) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ntlm: HTTP/2 and HTTP/3 requests are not supported");
        return NGX_ERROR;
    }
    pd = ngx_pcalloc(r->pool, sizeof(ngx_http_ntlm_peer_t));
    if (pd == NULL) {
        return NGX_ERROR;
    }
    pd->request = r;
    pd->conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);
    if (pd->conf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }
    pd->owner = ngx_http_ntlm_find_owner(r, pd->conf);
    if (r->headers_in.authorization) {
        auth = r->headers_in.authorization->value;
        pd->scheme = ngx_http_ntlm_scheme(&auth);
        if (pd->scheme == NGX_NTLM_AUTH || pd->scheme == NGX_NTLM_NEGOTIATE) {
            token = ngx_http_ntlm_decode(r, auth, pd->scheme, 0);
            if (token == NGX_ERROR) {
                return NGX_ERROR;
            }
            pd->token = token;
        }
    }
    pd->data = r->upstream->peer.data;
    pd->get = r->upstream->peer.get;
    pd->free = r->upstream->peer.free;
    pd->notify = r->upstream->peer.notify;
    r->upstream->peer.data = pd;
    r->upstream->peer.get = ngx_http_ntlm_get_peer;
    r->upstream->peer.free = ngx_http_ntlm_free_peer;
    r->upstream->peer.notify = ngx_http_ntlm_notify;
#if (NGX_HTTP_SSL)
    pd->set_session = r->upstream->peer.set_session;
    pd->save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_ntlm_set_session;
    r->upstream->peer.save_session = ngx_http_ntlm_save_session;
#endif
    return NGX_OK;
}

static ngx_uint_t
ngx_http_ntlm_expired(ngx_connection_t *c, ngx_http_ntlm_conf_t *conf)
{
    return c->close || c->read->eof || c->read->error || c->read->timedout
           || c->write->error || c->write->timedout
           || c->requests >= conf->max_requests
           || ngx_current_msec - c->start_time >= conf->time
           || (c->read->timer_set
               && (ngx_msec_int_t) (ngx_current_msec - c->read->timer.key) >= 0);
}

static ngx_int_t
ngx_http_ntlm_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_ntlm_peer_t     *pd = data;
    ngx_connection_t        *c;
    ngx_http_ntlm_session_t  *session;
    ngx_addr_t              *peer;

    pd->reused = 0;
    pd->session = NULL;
    if (pd->owner && pd->owner->connection) {
        c = pd->owner->connection;
        session = pd->owner->session;
        if (ngx_http_ntlm_expired(c, pd->conf)
            || (pd->scheme != NGX_NTLM_NO_AUTH
                && (pd->token != NGX_NTLM_RESPONSE_TOKEN || !session->pending
                    || pd->scheme != session->scheme)))
        {
            ngx_http_ntlm_cleanup(pd->owner);
        } else {
            /* Logging must outlive a socket closed or evicted in free_peer. */
            peer = ngx_http_ntlm_copy_peer(pd->request->pool, session->peer);
            if (peer == NULL) {
                return NGX_ERROR;
            }
            pd->session = session;
            pd->reused = 1;
            ngx_http_ntlm_detach(pd->owner);
            c->idle = 0;
            c->sent = 0;
            c->log = pc->log;
            c->read->log = pc->log;
            c->write->log = pc->log;
            c->pool->log = pc->log;
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }
            pc->sockaddr = peer->sockaddr;
            pc->socklen = peer->socklen;
            pc->name = &peer->name;
            pc->connection = c;
            pc->cached = 1;
            return NGX_DONE;
        }
    }
    return pd->get(pc, pd->data);
}

static ngx_int_t
ngx_http_ntlm_cache(ngx_http_ntlm_peer_t *pd, ngx_peer_connection_t *pc)
{
    ngx_http_request_t     *r = pd->request;
    ngx_connection_t       *c = pc->connection;
    ngx_pool_cleanup_t     *cln;
    ngx_http_ntlm_owner_t  *old;
    ngx_addr_t             peer;
    ngx_int_t              pending;

    if (pd->owner == NULL) {
        pd->owner = ngx_http_ntlm_find_owner(r, pd->conf);
    }
    if (pd->owner == NULL) {
#ifdef NGX_NTLM_TEST_CLEANUP_NULL
        cln = NULL;
#else
        cln = ngx_pool_cleanup_add(r->connection->pool,
                                  sizeof(ngx_http_ntlm_owner_t));
#endif
        if (cln == NULL) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                          "ntlm: failed to allocate cleanup handler");
            return NGX_ERROR;
        }
        pd->owner = cln->data;
        ngx_memzero(pd->owner, sizeof(ngx_http_ntlm_owner_t));
        pd->owner->conf = pd->conf;
        pd->owner->tag = r->upstream->conf;
        cln->handler = ngx_http_ntlm_cleanup;
    }
    if (pd->session == NULL) {
        pd->session = ngx_pcalloc(c->pool, sizeof(ngx_http_ntlm_session_t));
        if (pd->session == NULL) {
            return NGX_ERROR;
        }
        peer.sockaddr = pc->sockaddr;
        peer.socklen = pc->socklen;
        peer.name = *pc->name;
        pd->session->peer = ngx_http_ntlm_copy_peer(c->pool, &peer);
        if (pd->session->peer == NULL) {
            return NGX_ERROR;
        }
        pd->session->scheme = pd->scheme;
    }
    pending = ngx_http_ntlm_challenge(pd);
    if (pending == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (pending != NGX_DECLINED || pd->scheme != NGX_NTLM_NO_AUTH) {
        pd->session->pending = pending == 1;
    }

    /* Concurrent subrequests can finish with another idle socket already held. */
    ngx_http_ntlm_cleanup(pd->owner);
    if (pd->conf->cached == pd->conf->max_cached) {
        old = ngx_queue_data(ngx_queue_last(&pd->conf->cache),
                             ngx_http_ntlm_owner_t, queue);
        ngx_http_ntlm_cleanup(old);
    }
    pd->owner->connection = c;
    pd->owner->session = pd->session;
    ngx_queue_insert_head(&pd->conf->cache, &pd->owner->queue);
    pd->conf->cached++;

    pc->connection = NULL;
    c->data = pd->owner;
    c->idle = 1;
    c->read->delayed = 0;
    c->read->handler = ngx_http_ntlm_idle;
    c->write->handler = ngx_http_ntlm_dummy;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;
    ngx_add_timer(c->read, pd->conf->timeout);
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    if (c->read->ready) {
        ngx_http_ntlm_idle(c->read);
    }
    return NGX_OK;
}

static void
ngx_http_ntlm_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    ngx_http_ntlm_peer_t  *pd = data;
    ngx_http_upstream_t   *u = pd->request->upstream;
    ngx_connection_t     *c = pc->connection;
    ngx_uint_t            private;

    private = pd->reused || pd->scheme == NGX_NTLM_AUTH
              || pd->scheme == NGX_NTLM_NEGOTIATE;
    if (private && c && !(state & (NGX_PEER_FAILED|NGX_PEER_NEXT))
        && !ngx_http_ntlm_expired(c, pd->conf)
        && u->keepalive && u->request_body_sent && !ngx_terminate && !ngx_exiting
        && ngx_handle_read_event(c->read, 0) == NGX_OK)
    {
        if (ngx_http_ntlm_cache(pd, pc) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                          "ntlm: cannot retain private session, closing socket");
        }
    }
    if (pd->reused) {
        /* No peer selection occurred, so there is no balancer lease to free. */
        if (pc->tries) {
            pc->tries--;
        }
        return;
    }
    c = pc->connection;
    if (private) {
        pc->connection = NULL;
    }
    pd->free(pc, pd->data, state);
    if (private) {
        /* Core must close rejected private sockets, never share them. */
        pc->connection = c;
    }
}

static void
ngx_http_ntlm_notify(ngx_peer_connection_t *pc, void *data, ngx_uint_t type)
{
    ngx_http_ntlm_peer_t  *pd = data;

    if (!pd->reused && pd->notify) {
        pd->notify(pc, pd->data, type);
    }
}

static void
ngx_http_ntlm_dummy(ngx_event_t *ev)
{
}

static void
ngx_http_ntlm_idle(ngx_event_t *ev)
{
    ngx_connection_t      *c = ev->data;
    ngx_http_ntlm_owner_t *owner = c->data;
    ssize_t                n;
    char                   buf;

    if (c->close || ev->timedout) {
        ngx_http_ntlm_cleanup(owner);
        return;
    }
    n = recv(c->fd, &buf, 1, MSG_PEEK);
    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;
        if (ngx_handle_read_event(ev, 0) == NGX_OK) {
            return;
        }
    }
    ngx_http_ntlm_cleanup(owner);
}

static void
ngx_http_ntlm_close(ngx_connection_t *c)
{
    c->data = NULL;
    c->idle = 0;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;
#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_ntlm_close;
            return;
        }
    }
#endif
    ngx_destroy_pool(c->pool);
    c->pool = NULL;
    ngx_close_connection(c);
}

#if (NGX_HTTP_SSL)
static ngx_int_t
ngx_http_ntlm_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_ntlm_peer_t  *pd = data;

    if (!pc->connection || pc->cached || !pd->set_session) {
        return NGX_OK;
    }
    return pd->set_session(pc, pd->data);
}

static void
ngx_http_ntlm_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_ntlm_peer_t  *pd = data;

    if (pc->connection && !pc->cached && pd->save_session) {
        pd->save_session(pc, pd->data);
    }
}
#endif

static char *
ngx_http_ntlm_init_main_conf(ngx_conf_t *cf, void *data)
{
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_upstream_srv_conf_t  **us;
    ngx_http_ntlm_conf_t           *conf;
    ngx_uint_t                     i;

    /* Install outside built-in keepalive, including automatic injection. */
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    us = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (us[i]->srv_conf == NULL) {
            continue;
        }
        conf = ngx_http_conf_upstream_srv_conf(us[i],
                                               ngx_http_upstream_ntlm_module);
        if (!conf->enabled) {
            continue;
        }
        ngx_conf_init_uint_value(conf->max_cached, 100);
        ngx_conf_init_uint_value(conf->max_requests, 1000);
        ngx_conf_init_msec_value(conf->timeout, 60000);
        ngx_conf_init_msec_value(conf->time, 3600000);
        ngx_queue_init(&conf->cache);
        conf->original_init_peer = us[i]->peer.init;
        us[i]->peer.init = ngx_http_ntlm_init_peer;
    }
    return NGX_CONF_OK;
}

static void *
ngx_http_ntlm_create_conf(ngx_conf_t *cf)
{
    ngx_http_ntlm_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ntlm_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->max_cached = NGX_CONF_UNSET_UINT;
    conf->max_requests = NGX_CONF_UNSET_UINT;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->time = NGX_CONF_UNSET_MSEC;
    return conf;
}

static char *
ngx_http_ntlm_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    ngx_http_ntlm_conf_t          *conf = data;
    ngx_str_t                    *value;
    ngx_int_t                     n;

    if (conf->enabled) {
        return "is duplicate";
    }
    if (cf->args->nelts == 2) {
        value = cf->args->elts;
        n = ngx_atoi(value[1].data, value[1].len);
        if (n == NGX_ERROR || n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ntlm: invalid value \"%V\" in \"%V\" directive",
                               &value[1], &cmd->name);
            return NGX_CONF_ERROR;
        }
        conf->max_cached = n;
    }
    conf->enabled = 1;
    return NGX_CONF_OK;
}
