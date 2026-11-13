#!/bin/bash

source "$(dirname -- "${BASH_SOURCE[0]}")/build_common.sh"

cd "nginx-${NGINX_VERSION}"

make
