# nginx-ntlm-module

The NTLM module allows proxying requests with [NTLM Authentication](https://en.wikipedia.org/wiki/Integrated_Windows_Authentication). The upstream connection is bound to the client connection once the client sends a request with the "Authorization" header field value starting with "Negotiate" or "NTLM". Further client requests will be proxied through the same upstream connection, keeping the authentication context.

## How to use

> Syntax:  ntlm [connections];  
> Default: ntlm 100;  
> Context: upstream 


```nginx
upstream http_backend {
    server 127.0.0.1:8080;

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
    --add-module=../nginx-ntlm-module
```

To build this as dynamic module run this command

```bash
./configure \
    --add-dynamic-module=../nginx-ntlm-module
```

## Tests

In order to run the tests you need nodejs and perl installed on your system

```bash
# install the backend packages
npm install -C t/backend

# instal the test framework
cpan Test::Nginx

# set the path to your nginx location
export PATH=/opt/local/nginx/sbin:$PATH

prove -r t
```


## nginx Version Compatibility

| nginx version | Notes |
|---------------|-------|
| < 1.9.1       | Not supported — the upstream peer API used by this module was introduced in nginx 1.9.1. |
| 1.9.1 – 1.24.x | Supported. |
| ≥ 1.25.x      | Supported. Versions in the 1.25/1.26/1.27/1.28 series (e.g. 1.28.3) changed internal assumptions about `ngx_connection_t->data` in the upstream event handler (`ngx_http_upstream_handler` now expects `c->data` to hold the request pointer). Earlier releases of this module reused `c->data` to store the NTLM cache item on idle connections, which caused segfaults with these nginx versions. This was fixed in the module — see [PR #4](https://github.com/Securepoint/nginx-ntlm-module/pull/4). Use a module build from the current `main` branch when running nginx ≥ 1.25. |

## Acknowledgments

- This module is using most of the code from the original nginx keepalive module.
- DO NOT USE THIS IN PRODUCTION. [**Nginx Plus**](https://www.nginx.com/products/nginx/) has support for NTLM. 

## Authors 

* Gabriel Hodoroaga ([hodo.dev](https://hodo.dev))

## TODO

- [x] Add tests
- [x] Add support for multiple workers
- [x] Drop the upstream connection when the client connection drops.
- [ ] Add travis ci
