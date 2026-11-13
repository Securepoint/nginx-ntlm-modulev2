#!/bin/bash

source "$(dirname -- "${BASH_SOURCE[0]}")/build_common.sh"

cd "nginx-${NGINX_VERSION}"

./configure --with-debug \
            --prefix= \
            --conf-path=conf/nginx.conf \
            --pid-path=logs/nginx.pid \
            --http-log-path=logs/access.log \
            --error-log-path=logs/error.log \
            --with-pcre="../pcre2-${PCRE2_VERSION}" \
            --with-zlib="../zlib-${ZLIB_VERSION}" \
            --with-http_v2_module \
            --with-http_realip_module \
            --with-http_addition_module \
            --with-http_sub_module \
            --with-http_dav_module \
            --with-http_stub_status_module \
            --with-http_flv_module \
            --with-http_mp4_module \
            --with-http_gunzip_module \
            --with-http_gzip_static_module \
            --with-http_auth_request_module \
            --with-http_random_index_module \
            --with-http_secure_link_module \
            --with-http_slice_module \
            --with-mail \
            --with-stream \
            --with-openssl="../openssl-${OPENSSL_VERSION}" \
            --with-http_ssl_module \
            --with-mail_ssl_module \
            --with-stream_ssl_module \
            --add-module="$NTLM_MODULE_DIR"
