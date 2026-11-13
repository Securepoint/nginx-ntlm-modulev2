#!/bin/bash

set -euo pipefail

NGINX_VERSION=1.30.6
NGINX_SHA256=3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8
PCRE2_VERSION=10.49
PCRE2_SHA256=929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
ZLIB_VERSION=1.4
ZLIB_SHA256=02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584
NTLM_MODULE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

download_source() {
    local url="$1" checksum="$2" destination="$3"
    local archive="${url##*/}"

    curl --fail --show-error --location \
        --proto '=https' --proto-redir '=https' \
        "$url" -o "$archive"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 -c -
    else
        printf 'Install sha256sum or shasum before downloading build sources.\n' >&2
        return 1
    fi
    tar -xzf "$archive" -C "$destination"
    rm -- "$archive"
}

download_nginx() {
    download_source \
        "https://github.com/nginx/nginx/releases/download/release-${NGINX_VERSION}/nginx-${NGINX_VERSION}.tar.gz" \
        "$NGINX_SHA256" .
}

download_libraries() {
    local destination="$1"

    download_source \
        "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz" \
        "$PCRE2_SHA256" "$destination"
    download_source \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
        "$OPENSSL_SHA256" "$destination"
    download_source \
        "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" \
        "$ZLIB_SHA256" "$destination"
}
