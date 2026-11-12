# nginx-ntlm-modulev2

The NTLM module allows proxying requests with [NTLM Authentication](https://en.wikipedia.org/wiki/Integrated_Windows_Authentication). The upstream connection is bound to the client connection once the client sends a request with the "Authorization" header field value starting with "Negotiate" or "NTLM". Further client requests will be proxied through the same upstream connection, keeping the authentication context.

This is a full rewrite of the original [nginx-ntlm-module](https://github.com/Securepoint/nginx-ntlm-module), targeting **nginx ≥ 1.25** only. It is a 1:1 drop-in replacement for the original module in terms of configuration directives and behaviour, but does not support older nginx releases.

## HTTP/2 compatibility

This module is intentionally **incompatible with HTTP/2** for requests that
resolve to an `ntlm` upstream.

HTTP/2 can still be enabled for other servers/locations. When an HTTP/2
request reaches an `ntlm` upstream, the module rejects it and logs an error.

This guard is deliberate: NTLM connection pinning depends on
connection semantics that are not compatible with HTTP/2 multiplexing.

## Security improvements over v1

- **Session-hijack via cleanup-OOM (Critical)** — If `ngx_pool_cleanup_add()` returns NULL the upstream connection is no longer cached. Previously the connection was inserted into the cache with a stale `client_connection` pointer that nginx might later recycle for a different client, allowing `get_ntlm_peer` to hand an already-authenticated session to the wrong client (ABA pointer-reuse attack).

- **Stale-credential reuse (High)** — When a keep-alive client connection sends new `NTLM`/`Negotiate` credentials after the initial handshake has completed (`c->requests >= 2`), the old authenticated upstream session is now evicted and closed, forcing a fresh negotiation. Previously the old session was silently reused regardless of the new credentials.

- **Atomic item release** — A dedicated `ngx_http_upstream_ntlm_item_release()` helper is the single canonical code path for returning a cache item to the free list. It atomically clears `in_cache`, `peer_connection`, and `client_connection` before any queue operation, preventing any concurrent handler from operating on a partially-released item.

- **`c->data` segfault on nginx ≥ 1.25** — Upstream connections idle in the NTLM cache store the cache-item pointer in `c->read->data` instead of `c->data`. nginx's `ngx_http_upstream_handler()` requires `c->data` to hold the request pointer; overwriting it with the cache item caused segfaults on nginx ≥ 1.25.

- **Synchronous cleanup** — The client-connection pool cleanup handler closes the bound upstream connection synchronously. Earlier versions posted an event which could fire after the cache slot had already been reused, causing queue corruption and segfaults.

- **Cleanup ownership across upstream groups** — Each client connection registers cleanup separately for every NTLM upstream group it uses. Cleanup releases all matching cached sessions without retaining pointers to reusable cache slots. Cache lookup and cleanup match both the client connection pointer and its connection number, preventing a recycled address from selecting another client's session.

- **Shared-cache isolation** — NTLM connections rejected from the private cache, including request/age retirement and cleanup-allocation failure, are withheld from lower-layer shared keepalive caches. Balancer accounting still runs, and nginx core closes the rejected socket. Non-NTLM connections can still use shared keepalive normally.

- **HTTPS upstream session-reuse hardening** — NTLM now skips upstream SSL session set/save callbacks for reused cached connections and guards null callback/connection states. This prevents invalid TLS session operations on already-handshaken pinned connections and avoids NULL-connection crashes in upstream SSL session handling paths.

## How to use

> Syntax:  ntlm [connections];  
> Default: ntlm 100;  
> Context: upstream 


```nginx
upstream http_backend {
    server 127.0.0.1:8080;

    keepalive 16;
    ntlm;
}

server {
    ...

    location /http/ {
        proxy_pass http://http_backend;
        # next 2 settings are required for the keepalive to work properly
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

The connections parameter sets the maximum number of connections to the upstream servers that are preserved in the cache.
If you configure explicit upstream keepalive, declare `keepalive` **before** `ntlm` in the same `upstream` block; nginx applies wrappers by directive chaining, and this order keeps NTLM as the outermost peer wrapper so authenticated connection pinning is preserved.

> Syntax:  ntlm_timeout timeout;  
> Default: ntlm_timeout 60s;  
> Context: upstream  

Sets the timeout during which an idle connection to an upstream server will stay open.

> Syntax:  ntlm_time time;  
> Default: ntlm_time 1h;  
> Context: upstream  

Sets the maximum wall-clock age of a cached upstream connection. Once the connection has been open for longer than this value it will not be reused, even if it is otherwise idle and healthy. This bounds the lifetime of a single NTLM authentication context.

> Syntax:  ntlm_requests number;  
> Default: ntlm_requests 1000;  
> Context: upstream  

Sets the maximum number of requests that may be made over a single cached upstream connection before it is closed and a new one is established. Limiting the number of requests per connection prevents a single long-lived connection from accumulating unbounded state.

## Build 

Follow the instructions from [Building nginx from Sources](http://nginx.org/en/docs/configure.html) and add the following line to the configure command

```bash 
./configure \
    --add-module=../nginx-ntlm-modulev2
```

To build this as a dynamic module run:

```bash
./configure \
    --add-dynamic-module=../nginx-ntlm-modulev2
```

## Tests

In order to run the tests you need nodejs and perl installed on your system

```bash
# install the backend packages
npm install -C t/backend

# install the test framework
cpan Test::Nginx

# set the path to your nginx location
export PATH=/opt/local/nginx/sbin:$PATH

prove -r t
python3 -m unittest discover -s t -p 'test_*.py'
```

The ownership regression tests require Python 3 (standard library only) and an
nginx binary built with this module. They cover multi-upstream disconnect
cleanup, cache-slot reassignment, session isolation across new clients, and
rejected-session isolation from shared keepalive caches. Shared-cache tests use
`max_conns=1` to also exercise balancer accounting.

To include the cleanup-allocation failure regression, build a second nginx
binary with `--with-cc-opt="-DNGX_NTLM_TEST_CLEANUP_NULL"` and run:

```bash
TEST_NGINX_BINARY=/path/to/normal/nginx \
TEST_NGINX_CLEANUP_NULL_BINARY=/path/to/fault-injection/nginx \
python3 -m unittest discover -s t -p 'test_*.py'
```

## nginx Version Compatibility

| nginx version | Notes |
|---------------|-------|
| < 1.25        | Not supported. |
| ≥ 1.25        | Supported. This module targets nginx 1.25 and later. It correctly stores cache-item pointers in `c->read->data` (not `c->data`) to avoid the segfault regression introduced in the 1.25/1.26/1.27/1.28 series. |
| master (1.31+) | Supported. See [nginx master compatibility](#nginx-master-compatibility) below. |

## nginx master compatibility

nginx master (≥ 1.31) introduced **automatic keepalive injection**: the built-in
`ngx_http_upstream_keepalive_module` now installs a peer wrapper for every
upstream in its `init_main_conf` hook — even when no explicit `keepalive N`
directive is present.  If the NTLM module's peer wrapper was installed during
`init_upstream` (as it was in earlier versions of this module), the keepalive
wrapper ended up on the *outside*, intercepting `free_peer` calls before NTLM
could pin the upstream connection.  The keepalive module then cached the
connection itself and set `pc->connection = NULL`, causing NTLM's `free_peer`
to bail out via the `c == NULL` guard — so NTLM never registered the connection
in its own cache.  Subsequent requests were round-robined across servers rather
than staying pinned to the authenticated upstream.

**Fix (shipped in this version):** The peer-init wrapping was moved from
`ngx_http_upstream_init_ntlm` (`init_upstream`) to a new
`ngx_http_upstream_ntlm_init_main_conf` (`init_main_conf`) hook.
`--add-module` extensions are assigned higher module indices than all built-in
modules, so NTLM's `init_main_conf` always runs *after* the keepalive module's
`init_main_conf`.  This keeps NTLM as the outermost peer wrapper regardless of
nginx version.

## Acknowledgments

- This module is based on the original nginx-ntlm-module by Gabriel Hodoroaga.
- This module is community-maintained. For enterprise environments requiring vendor support or SLA guarantees, consider [**Nginx Plus**](https://www.nginx.com/products/nginx/), which has built-in NTLM support.

## Authors 

* Gabriel Hodoroaga ([hodo.dev](https://hodo.dev)) — original module
* Securepoint — v2 rewrite and security hardening

## Changelog

### v2
- Full rewrite targeting nginx ≥ 1.25
- Fix session hijack via cleanup-OOM (Critical)
- Fix stale-credential reuse (High)
- Fix `c->data` segfault on nginx ≥ 1.25
- Add atomic item-release helper
- Synchronous client-connection cleanup (no posted events)
- Add `ntlm_time` and `ntlm_requests` directives
- Add `notify` peer callback pass-through
- Fix NTLM pinning broken on nginx master (≥ 1.31): move peer-init wrapping
  to `init_main_conf` so NTLM is always the outermost peer wrapper, even when
  the keepalive module auto-injects its own wrapper
