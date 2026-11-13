# nginx-ntlm-modulev2

The NTLM module allows proxying requests with [NTLM Authentication](https://en.wikipedia.org/wiki/Integrated_Windows_Authentication). The upstream connection is bound to the client connection once the client sends a request with the "Authorization" header field value starting with "Negotiate" or "NTLM". Further client requests will be proxied through the same upstream connection, keeping the authentication context.

This module targets **nginx ≥ 1.26.3**, retaining the original
[nginx-ntlm-module](https://github.com/Securepoint/nginx-ntlm-module) directives.
The session lifecycle has been redesigned from `main`, independently of the
`fix/ntlm-session-ownership` commit history.

## Session ownership and keepalive

Each client connection has a stable, pool-owned handle for each upstream and
proxy configuration it uses. That handle directly owns at most one idle
upstream connection. Client cleanup, timeout, eviction and credential replacement
all detach the handle before closing its socket. Active connections belong to
nginx upstream core instead. There are no reusable cache slots, stale slot
cleanup pointers, global owner lookups, or connection-address generation checks.

The upstream LRU only limits idle capacity. A private hit is resolved **before**
calling the balancer or shared keepalive pool, and retains its real backend
address. Only attempts that selected a peer delegate balancer free/notify
callbacks. Authenticated sockets rejected from private caching are closed by
core, never placed into a shared pool. Ordinary anonymous requests still use
native shared keepalive.

Idle handling follows nginx's built-in keepalive model: event data always points
to the connection, while `c->data` points to its owner only after installing idle
handlers. Core restores request data on reuse. This supports event-backend
operations and SSL shutdown without changing their expected pointer types.

Authentication continuation requires a matching server challenge on that socket.
New NTLM Type-1 or SPNEGO initial tokens, malformed continuation envelopes,
attempted continuations after completion and scheme changes retire the old socket. Type-3 and
SPNEGO responses can continue only a pending exchange. Neither request counts
nor HTTP status prove that authentication completed; mechanism credentials
remain the backend's responsibility.

Bare or invalid matching challenges do not hide later token-bearing challenges,
whether combined in one header or sent as separate headers. The first valid
matching continuation or explicit SPNEGO completion/rejection determines the
pending state.

**Behavioral boundaries:**

- Sessions are deliberately isolated by proxy configuration, not just upstream
  name. Different locations with distinct proxy configurations do not inherit
  each other's NTLM identity or upstream TLS settings. A client changing
  configuration may need to authenticate again.
- HTTP/2 and HTTP/3 requests resolving to an `ntlm` upstream are rejected and
  logged. Other locations can still use those protocols.
- Private hits do not create a new balancer reservation. `max_conns`, new-peer
  selection and passive failure accounting apply to selected peers, not private
  hits. `max_conns` is therefore not a total authenticated-socket limit.
- Failed or retry-rejected pinned sockets are closed. Normal nginx retry policy
  can select a replacement, but authentication state cannot move to it.

### Authorization header passthrough

The module classifies authentication using the client's incoming `Authorization`
header, not the outgoing header evaluated by `proxy_set_header`. On an `ntlm`
upstream, preserve that header unchanged; ordinary proxy header passthrough is
the supported configuration.

Do not inject NTLM/Negotiate credentials from another header or variable, for
example with `proxy_set_header Authorization $http_x_ntlm_authorization;`.
If the incoming `Authorization` header is absent, the module treats the request
as anonymous even though the backend receives credentials. With shared upstream
keepalive, the authenticated socket can then enter the shared pool and serve a
different client's request under the previous client's backend identity.
This requires neither a shared downstream connection nor an attacker-controlled
intermediary: separate downstream connections can reuse a shared upstream socket.
Rewriting or suppressing credentials can also prevent the module from correctly
detecting credential changes and authentication continuations.

Authorization rewriting is not currently rejected by configuration validation.
This is a usage restriction, not an implemented security fix. Integrations that
require rewriting need the module to track the effective outgoing credentials
before peer selection; disabling shared keepalive alone does not repair
credential-change tracking. Ordinary unchanged Authorization passthrough does
not have this header-classification mismatch.

### Connection identity and forward proxies

The ownership key is the downstream connection plus the upstream/proxy
configuration, **not a user identity or client IP address**. Requests without
Authorization reuse the backend identity already bound to that connection.

If a forward proxy terminates client HTTP/TLS and pools requests from different
users onto the same HTTP/1.1 connection to nginx, the module cannot distinguish
those users. A request without its own Authorization can then use another user's
authenticated backend session, provided it reaches the same proxy configuration
while that session is retained. An attacker would not need to hijack or read the
victim's TCP connection: the forward proxy itself would perform the mixing.
However, the attacker would need their request to reach that particular shared
connection; using the same company proxy or public IP address is not sufficient.

This is a deployment/security boundary of connection-bound authentication, not a
generally confirmed high-severity vulnerability in this module. The regression
tests have not demonstrated a practical cross-user attack through such a forward
proxy. They separately demonstrate authentication continuity problems with
parallel subrequests; serializing those requests would not recover user identity
after a forward proxy has already combined users.

Require forward proxies to preserve connection separation for NTLM. HTTPS via
CONNECT with a separate, end-to-end TLS connection for each client connection
prevents HTTP-level request pooling inside those opaque tunnels. This assumes
TLS is not intercepted and the client validates the intended server certificate.
Ordinary certificate validation does not rule out interception if the client
trusts the intercepting proxy's CA. Neither this module nor TCP passthrough can
undo user mixing that has already occurred before traffic reaches nginx.

## Investigation of the earlier fixes

The earlier commits are evidence and regression references, **not ancestors of
this implementation**. The redesign was introduced as one new commit directly
on `main`; behavioral test fixtures are reused without their commit history.

| Earlier change | Problem it attempted to address | Assessment |
| --- | --- | --- |
| `ffbb875` | Disconnect cleanup missed upstream groups and retained reassigned cache slots. | Correct diagnosis. Direct client-pool ownership removes both failure modes without scanning the global cache or matching connection numbers. |
| `e1657b8` | HTTP/2 multiplexing breaks connection-bound authentication. | Preserve the restriction and cover HTTP/3 too. |
| `1c6bab3` | Invalid SSL callback delegation and stale cache entries. | Callback guards alone do not repair SSL-less compatible builds. Its stale-entry release also changes the queue being traversed without saving the next position. Neither problem exists in the new owner lookup. |
| `ce3608c`, `45cc7f3` | Rejected NTLM sockets leaked into shared keepalive. | Preserve isolation, but centralize lease release separately from socket ownership. |
| `20638a0` | Shared-cache hits bypassed pinning; expired sessions and multiplexed protocols needed handling. | Allowing private lookup after shared selection retains the wrong peer reservation/address and can consume an unrelated shared socket. Resolve ownership first instead. |
| `bc90508` | Request counts and HTTP statuses incorrectly inferred negotiation state. | Correct direction, but Type-1 alone still set pending state even without a challenge. Request SPNEGO continuation checked only a leading byte; some malformed challenge envelopes also passed. Validate the response envelope and derive pending state from the server. |

Additional inherited or retained defects found during the investigation:

- The old `c->read->data` layout violates nginx's event API. A select/TLS
  regression disconnects against the old branch; native idle ownership fixes
  the underlying pointer-type mismatch.
- New peer selection can return 502 despite a usable private socket, and
  `$upstream_addr` can report a different backend than the socket actually used.
- Explicit Basic or other credentials could retain a prior NTLM identity.
  Distinct proxy configurations could also inherit each other's sessions.
- A `NGX_PEER_NEXT` result could re-cache the just-rejected private socket and
  select it again instead of honoring next-upstream policy.
- Duplicate `ntlm` directives could recursively wrap initialization.
  A later balancing-method directive could also bypass NTLM cache initialization.
  The new `ntlm` directive only enables configuration; it no longer wraps
  `init_upstream` at all.
- As detailed in [issue #13](https://github.com/Securepoint/nginx-ntlm-modulev2/issues/13),
  an SSL-less `--with-compat` module can load into SSL-enabled nginx without its
  SSL callback wrappers. The underlying callback then receives the wrong
  `peer.data`, causing a reproduced TLS crash. Compatible builds now require
  `--with-http_ssl_module` during both configuration and compilation.

The regression suite reproduces the old branch's busy-peer, backend-address,
credential-scheme, proxy-scope, retry and negotiation failures. The historical
worker lock-wait report does not prove that every failure had the same cause.
Real Exchange/Outlook soak testing and Kerberos realm acceptance remain separate
deployment checks.

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

The connections parameter limits idle private connections per upstream per
worker, not active sockets or all connections across workers. Explicit
`keepalive` can be placed before or after `ntlm`: peer wrapping happens after
built-in wrappers during `init_main_conf`, rather than depending on directive
order.

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

## Alternative: TCP/TLS passthrough with stream

If nginx only needs to forward connections, its built-in
[`stream` proxy](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html)
can replace the HTTP proxy and this NTLM module. For TCP, each accepted client
connection gets its own backend connection; nginx does not pool HTTP requests
from different connections or create HTTP subrequests.

For HTTPS, TLS passthrough preserves the original TLS session all the way to
the backend. The backend handles TLS, HTTP and NTLM; nginx forwards encrypted
bytes without interpreting authentication. For example:

```nginx
# Main nginx.conf context, alongside (not inside) http {}.
stream {
    upstream ntlm_tls_backend {
        server 192.0.2.10:443;
    }

    server {
        listen 443;
        proxy_pass ntlm_tls_backend;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;
    }
}
```

Replace the example backend address with the actual service address. Use a
build with `--with-stream`, or load the distribution's dynamic stream module.
Pure TLS passthrough does not require `--with-stream_ssl_module`. Do not add
`ssl` to this listener or enable `proxy_ssl`: TLS is already carried inside
the forwarded byte stream. Configure the backend certificate for the public
hostname clients use; there is no certificate or TLS termination on this nginx
listener. `proxy_timeout` is an inactivity timeout, not a maximum session age;
adjust it for the application's long-lived connections.

| Aspect | Advantage | Trade-off |
| --- | --- | --- |
| Connection ownership | One backend TCP connection per downstream TCP connection, without HTTP keepalive pooling or NTLM-specific ownership code. | More backend connections; backend sizing and connection limits still matter. |
| TLS passthrough | End-to-end encryption and backend certificate validation by the client; no private TLS keys required on nginx. | Certificate management and TLS policy move to the backend. nginx cannot inspect the encrypted HTTP traffic. |
| HTTP features | Avoids HTTP proxy transformations and nginx-generated subrequests on this path. | No nginx URL/path routing, HTTP authentication, header rewriting, HTTP caching, WAF inspection or per-request HTTP logs on this path. Connection-level controls and stream logs remain available. |
| Balancing and failure | A connected TCP session stays with its chosen backend. | Balancing is per connection, not per request. A lost established session cannot migrate or replay its NTLM state; clients must reconnect and authenticate again. |
| Client address | Original application bytes are preserved. | The backend normally sees nginx's source IP. PROXY protocol is an option only if the backend explicitly supports it; it cannot be replaced with an injected HTTP header inside TLS. |

`stream` and `http` can coexist, but cannot independently listen on the same
address and port. Use different addresses/ports, or a stream entry point with
[`ssl_preread`](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)
to route by visible TLS SNI: send the NTLM hostname directly to its backend and
other hostnames to an internal HTTP-module TLS listener. This requires
`--with-stream_ssl_preread_module`; it does not provide URL/path routing within
an encrypted hostname.

### SNI routing with ssl_preread

For example, expose `mail.example.com` and `www.example.com` on the same public
TCP port 443. Replace the preceding stream example with these top-level
`stream` and `http` sections, retaining the rest of your nginx configuration:

```nginx
stream {
    map $ssl_preread_server_name $tls_destination {
        mail.example.com ntlm_tls_backend;
        www.example.com local_https;
        default         local_https;
    }

    upstream ntlm_tls_backend {
        server 192.0.2.10:443;
    }

    upstream local_https {
        server 127.0.0.1:8443;
    }

    server {
        listen 443;
        ssl_preread on;
        proxy_pass $tls_destination;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;
    }
}

http {
    server {
        listen 127.0.0.1:8443 ssl default_server;
        ssl_reject_handshake on;
    }

    server {
        listen 127.0.0.1:8443 ssl;
        server_name www.example.com;

        ssl_certificate     /etc/nginx/certs/www.example.com/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/www.example.com/privkey.pem;

        location / {
            proxy_pass http://192.0.2.20:8080;
            proxy_set_header Host $host;
        }
    }
}
```

Replace the example hostnames, backend addresses and certificate paths. This
configuration needs `--with-stream --with-stream_ssl_preread_module` and
`--with-http_ssl_module`, or equivalent loaded distribution modules.

The public stream listener reads the TLS ClientHello without terminating TLS.
For `mail.example.com`, the mail backend presents its certificate and handles
NTLM directly. For `www.example.com`, the original TLS stream reaches nginx's
loopback HTTP listener, which terminates TLS and can use normal HTTP features.
Unknown or missing SNI is sent to that listener's rejecting default server.
Only the stream listener binds public port 443; the HTTP listener must stay on
the distinct loopback port to avoid a bind conflict or routing loop.

Passthrough is not an HTTP/2 or HTTP/3 compatibility fix for NTLM. TCP passthrough
does not carry QUIC/HTTP/3, and TLS ALPN/HTTP-version negotiation remains between
the client and backend. Keep the NTLM endpoint on a protocol the backend supports
for connection-bound authentication, normally HTTP/1.1.

**Choose stream passthrough** when connection-level forwarding is sufficient.
**Keep this module** when nginx must act as an HTTP reverse proxy and its HTTP
features are required. In either case, a preceding proxy must not mix users
within one connection-bound authentication session.

## Build 

Follow the instructions from [Building nginx from Sources](http://nginx.org/en/docs/configure.html) and add the following line to the configure command

```bash 
./configure \
    --with-http_ssl_module \
    --add-module=../nginx-ntlm-modulev2
```

To build this as a dynamic module run:

```bash
./configure \
    --with-compat \
    --with-http_ssl_module \
    --add-dynamic-module=../nginx-ntlm-modulev2
```

Compatible modules must be built with `--with-http_ssl_module`, even when only
producing a `.so`; retain the other build options required by your target nginx.
Non-compatible HTTP-only static builds remain supported. The repaired module
does not require disabling `proxy_ssl_session_reuse`.

### Platform build helpers

The `utils/build_{linux,macos,win}_{download,configure,make}.sh` helpers use
shared source pins in `utils/build_common.sh`: nginx 1.30.6, PCRE2 10.49,
OpenSSL 3.5.9 (LTS), and zlib 1.4. Downloads use HTTPS-only redirects and
verify pinned SHA-256 digests from the projects' official GitHub release assets
before extraction. Update each version and its checksum together.

Run the helpers with Bash from a writable build directory, keeping the same
working directory for all three stages. Sources are extracted there; the module
path is resolved from the helper's location, regardless of the checkout name.
For example:

```bash
bash /path/to/nginx-ntlm-modulev2/utils/build_linux_download.sh
bash /path/to/nginx-ntlm-modulev2/utils/build_linux_configure.sh
bash /path/to/nginx-ntlm-modulev2/utils/build_linux_make.sh
```

Install a C build toolchain, Make, Perl, curl, tar, and either `sha256sum` or
`shasum`. On Windows, use an MSYS2 Bash environment with the Visual Studio 2022
x64 tools available, plus a compatible Windows Perl and NASM for OpenSSL.
The Windows make helper prints the native `nmake /f objs/Makefile` command;
it does not execute it. macOS requires the Xcode command-line tools.

## Tests

The tests need Node.js, Perl, Python 3 and the OpenSSL CLI. For the Python suite,
build nginx with `--with-debug --with-select_module --with-http_ssl_module
--with-http_v2_module --with-http_v3_module`.

```bash
# install the backend packages
npm install -C t/backend

# install the test framework
cpan Test::Nginx

python3 -m venv .venv
. .venv/bin/activate
pip install -r t/requirements.txt

# set the path to your nginx location
export PATH=/opt/local/nginx/sbin:$PATH

prove -r t
python3 -m unittest discover -s t -p 'test_*.py'
```

The standard-library ownership tests cover disconnect cleanup, eviction,
multi-upstream and proxy-configuration isolation, retry policy, balancer
accounting, idle/age/request retirement and TLS lifecycle with default and select
event backends. Protocol tests use real NTLM/SPNEGO exchanges and
certificate-verified TLS 1.2/1.3, shared upstream zones with SSL session reuse on,
HTTP/2 and HTTP/3. Credentials are synthetic and temporary.
Two simultaneously connected, authenticated clients are also checked for
separate retained backend sockets while an anonymous third client is rejected.

Parallel ownership tests use SSI subrequests to the same proxy configuration.
Backend barriers establish overlap, and nginx debug traces establish upstream
finalization before releasing the other response, in both completion orders.
They check that an additional request without Authorization uses an anonymous
socket without replacing the pinned session, while parallel requests with
explicit credentials retain the last completed private socket. These tests use
synthetic authorization markers; they do not verify concurrent NTLM handshakes
or demonstrate an authentication bypass.

Parallel protocol tests additionally use real NTLM challenges and responses in
both completion orders. They characterize the single retained challenge socket
and the loss of an authenticated socket when a failed parallel continuation
finishes last. They also cover downstream abort while upstreams are active,
backend disconnect with retries disabled or enabled, and `proxy_next_upstream`
on HTTP 403. Retry tests keep the primary busy to force a backup, verify that
authentication is not transferred to it, and check subsequent reauthentication.

To exercise cleanup-allocation failure, build a second binary with
`--with-cc-opt="-DNGX_NTLM_TEST_CLEANUP_NULL"` and export
`TEST_NGINX_CLEANUP_NULL_BINARY=/absolute/path/to/that/nginx`.
For dynamic builds, set `TEST_NGINX_BINARY` and
`TEST_NGINX_MODULE=/absolute/path/to/ngx_http_upstream_ntlm_module.so` when running
the Python suite. CI covers nginx 1.26.3, 1.30.0 and master.

## nginx Version Compatibility

| nginx version | Notes |
|---------------|-------|
| < 1.26.3      | Not supported. |
| ≥ 1.26.3      | Supported. Idle handling uses native nginx event-data ownership. |
| master (1.31+) | Supported. See [nginx master compatibility](#nginx-master-compatibility) below. |

## nginx master compatibility

Recent nginx versions introduced **automatic keepalive injection**: the built-in
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

**Current implementation:** `ngx_http_ntlm_init_main_conf` initializes the idle
LRU and wraps the fully initialized peer factory. The `ntlm` directive does not
alter `init_upstream`, so later balancing-method directives cannot bypass NTLM
cache initialization.
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
- Full rewrite targeting nginx ≥ 1.26.3
- Fix session hijack via cleanup-OOM (Critical)
- Fix stale-credential reuse (High)
- Use native nginx event-data ownership during idle caching and TLS teardown
- Replace reusable cache slots with stable client-owned handles and an idle LRU
- Resolve private sessions before new peer selection, keeping real backend metadata
- Validate NTLM/SPNEGO continuation against matching server challenges
- Isolate proxy configurations and retire sessions on credential-scheme changes
- Guard compatible builds against missing upstream SSL callback support
- Synchronous client-connection cleanup (no posted events)
- Add `ntlm_time` and `ntlm_requests` directives
- Add `notify` peer callback pass-through
- Fix NTLM pinning broken on nginx master (≥ 1.31): move peer-init wrapping
  to `init_main_conf` so NTLM is always the outermost peer wrapper, even when
  the keepalive module auto-injects its own wrapper
