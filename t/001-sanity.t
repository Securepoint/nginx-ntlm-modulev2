use String::Random;
use Test::Nginx::Socket 'no_plan';

#workers(2);
repeat_each(2);

my $string_gen = String::Random->new;
our $random_token  = $string_gen->randpattern("CcCcCcCCcC");
our $random_token2;
do { $random_token2 = $string_gen->randpattern("CcCcCcCCcC"); } while $random_token2 eq $random_token;

# Start the nodejs backend
my $pid = fork();
if ($pid == 0) {  #child
    exec("node t/backend/index.js");
} else { #parent
    sleep 1;
}

add_cleanup_handler(sub {
    kill INT => $pid;
});

run_tests();

__DATA__

=== TEST 1: NTLM header should trigger keepalive for upstream
When the authorization header contains NTLM the token is saved on the server
connection and all subsequent requests should return it in X-NGX-NTLM-AUTH 
header
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm; 
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval 
["GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Authorization: NTLM " . $::random_token,"",""]
--- response_body eval 
["OK", "OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::random_token, "X-NGX-NTLM-AUTH: " . $::random_token, "X-NGX-NTLM-AUTH: " . $::random_token]
--- no_error_log
[error]


=== TEST 2: Negotiate header should trigger keepalive for upstream
When the authorization header contains Negotiate the token is saved on the server
connection and all subsequent requests should return it in X-NGX-NTLM-AUTH 
header
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval 
["GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Authorization: Negotiate " . $::random_token,"",""]
--- response_body eval 
["OK", "OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::random_token, "X-NGX-NTLM-AUTH: " . $::random_token, "X-NGX-NTLM-AUTH: " . $::random_token]
--- no_error_log
[error]


=== TEST 3: The backend connection should die when client connection dies
When the authorization header contains NTLM the token is saved on the server
connection if the client drops the connection the backend connection must die 
also
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm; 
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- request eval 
["GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Authorization: NTLM " . $::random_token,"",""]
--- response_body eval 
["OK", "OK", "OK"]
--- raw_response_headers_like eval
["X-NGX-NTLM-AUTH: " . $::random_token, "", ""]
--- raw_response_headers_unlike eval
["========","X-NGX-NTLM-AUTH: ","X-NGX-NTLM-AUTH: "]
--- no_error_log
[error]


=== TEST 4: The backend connection should die when client connection dies
When the authorization header contains Negotiate the token is saved on the server
connection if the client drops the connection the backend connection must die 
also
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm; 
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- request eval 
["GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Authorization: Negotiate " . $::random_token,"",""]
--- response_body eval 
["OK", "OK", "OK"]
--- raw_response_headers_like eval
["X-NGX-NTLM-AUTH: " . $::random_token, "", ""]
--- raw_response_headers_unlike eval
["========","X-NGX-NTLM-AUTH: ","X-NGX-NTLM-AUTH: "]
--- no_error_log
[error]


=== TEST 5: New NTLM credentials on an established connection must evict the old session
After the initial NTLM handshake completes (upstream connection has served at
least 2 requests), presenting new credentials on the same keep-alive client
connection must not reuse the old authenticated upstream session.  The module
must evict the old session and obtain a fresh upstream connection so the new
credentials are negotiated independently.
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval
["GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Authorization: NTLM " . $::random_token, "", "Authorization: NTLM " . $::random_token2]
--- response_body eval
["OK", "OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::random_token, "X-NGX-NTLM-AUTH: " . $::random_token, "X-NGX-NTLM-AUTH: " . $::random_token2]
--- no_error_log
[error]


# ── TEST 6: OOM in cleanup handler must not cache the upstream connection ──
#
# To run this test you need a build with the fault-injection flag enabled:
#
#   ./configure --add-module=/path/to/nginx-ntlm-modulev2 \
#               --with-cc-opt="-DNGX_NTLM_TEST_CLEANUP_NULL"
#   make
#
# The flag makes ngx_pool_cleanup_add() always return NULL inside the module,
# exercising the OOM guard in ngx_http_upstream_free_ntlm_peer.  Without this
# guard the module would cache the connection with a stale client_connection
# pointer, enabling a session-hijack via pointer reuse (ABA attack).
#
=== TEST 6: OOM in cleanup handler must not cache the upstream connection
When ngx_pool_cleanup_add returns NULL the upstream session MUST NOT be
inserted into the cache.  A subsequent request on the same client connection
must therefore NOT inherit the old authenticated upstream session.
This test requires a build with -DNGX_NTLM_TEST_CLEANUP_NULL.
--- SKIP
--- http_config
    upstream backend {
        server localhost:19841;
        ntlm;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval
["GET /t", "GET /t"]
--- more_headers eval
["Authorization: NTLM " . $::random_token, "Authorization: NTLM " . $::random_token]
--- response_body eval
["OK", "OK"]
--- error_log
ntlm: failed to allocate cleanup handler
--- raw_response_headers_unlike eval
["========", "X-NGX-NTLM-AUTH: "]

