BEGIN {
    unless ($ENV{NGX_NTLM_TEST_CLEANUP_NULL}) {
        require Test::More;
        Test::More::plan(skip_all => 'requires NGX_NTLM_TEST_CLEANUP_NULL build');
        exit 0;
    }
}

use String::Random;
use Test::Nginx::Socket 'no_plan';

#workers(2);
repeat_each(2);

my $string_gen = String::Random->new;
our $random_token = $string_gen->randpattern("CcCcCcCCcC");

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

=== TEST 1: OOM in cleanup handler must not cache the upstream connection
When ngx_pool_cleanup_add returns NULL the upstream session MUST NOT be
inserted into the cache. A subsequent request on the same client connection
must therefore NOT inherit the old authenticated upstream session.
This test requires a build with -DNGX_NTLM_TEST_CLEANUP_NULL.
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
["Authorization: NTLM " . $::random_token, ""]
--- response_body eval
["OK", "OK"]
--- response_headers eval
["X-NGX-NTLM-AUTH: " . $::random_token, ""]
