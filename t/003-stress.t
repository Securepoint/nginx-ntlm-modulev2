use String::Random;
use Test::Nginx::Socket 'no_plan';

workers(4);
repeat_each(3);

my $string_gen = String::Random->new;
my %seen_tokens;

sub unique_token {
    my $token;
    do { $token = $string_gen->randpattern("CcCcCcCCcC"); } while $seen_tokens{$token}++;
    return $token;
}

our $token_a = unique_token();
our $token_b = unique_token();
our $token_c = unique_token();
our $token_requests = unique_token();
our $token_time = unique_token();
our $token_pipeline = unique_token();
our $token_x = unique_token();
our $token_y = unique_token();

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

=== TEST 1: Cache eviction under cache saturation
When the cache has only 2 slots and 3 different credentials are used
sequentially, the oldest entry must be evicted without list corruption.
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm 2;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- request eval
["GET /t/a", "GET /t/b", "GET /t/c"]
--- more_headers eval
["Authorization: NTLM " . $::token_a, "Authorization: NTLM " . $::token_b, "Authorization: NTLM " . $::token_c]
--- response_body eval
["OK", "OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::token_a, "X-NGX-NTLM-AUTH: " . $::token_b, "X-NGX-NTLM-AUTH: " . $::token_c]
--- no_error_log
\[error\]


=== TEST 2: max_requests boundary should retire connection at limit
With ntlm_requests set to 3, the 4th pipelined request on the same client
connection must not reuse the previous authenticated upstream connection.
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm;
        ntlm_requests 3;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval
["GET /t", "GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Authorization: NTLM " . $::token_requests, "", "", ""]
--- response_body eval
["OK", "OK", "OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::token_requests, "X-NGX-NTLM-AUTH: " . $::token_requests, "X-NGX-NTLM-AUTH: " . $::token_requests, ""]
--- raw_response_headers_unlike eval
["==========", "==========", "==========", "X-NGX-NTLM-AUTH: "]
--- no_error_log
\[error\]


=== TEST 3: ntlm_time wall-clock age should retire old connection
After ntlm_time has elapsed, a follow-up request must not inherit old auth.
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm;
        ntlm_time 2s;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval
["GET /t/1", [{value => "GET /t/2", delay_before => 3}]]
--- more_headers eval
["Authorization: NTLM " . $::token_time, ""]
--- response_body eval
["OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::token_time, ""]
--- raw_response_headers_unlike eval
["==========", "X-NGX-NTLM-AUTH: "]
--- no_error_log
\[error\]
--- SKIP # pipelined_requests does not support spliting into packets ... yet


=== TEST 4: Deep pipelining on a single pinned connection
Stress a single pinned session with 10 pipelined requests.
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm 10;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval
["GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Authorization: NTLM " . $::token_pipeline, "", "", "", "", "", "", "", "", ""]
--- response_body eval
["OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline, "X-NGX-NTLM-AUTH: " . $::token_pipeline]
--- no_error_log
\[error\]


=== TEST 5: Simultaneous independent sessions should not cross-contaminate
Two sequential session setups using different tokens must keep responses isolated
to their own session token.
--- http_config
    upstream backend {
        server localhost:19841;
        server localhost:19842;
        ntlm 10;
    }
--- config
    location /t {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
--- pipelined_requests eval
["GET /t/x/1", "GET /t/x/2", "GET /t/y/1", "GET /t/y/2"]
--- more_headers eval
["Authorization: NTLM " . $::token_x, "", "Authorization: NTLM " . $::token_y, ""]
--- response_body eval
["OK", "OK", "OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::token_x, "X-NGX-NTLM-AUTH: " . $::token_x, "X-NGX-NTLM-AUTH: " . $::token_y, "X-NGX-NTLM-AUTH: " . $::token_y]
--- no_error_log
\[error\]
