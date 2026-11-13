#!/bin/bash

source "$(dirname -- "${BASH_SOURCE[0]}")/build_common.sh"

download_nginx
mkdir -p "nginx-${NGINX_VERSION}/objs/lib"
download_libraries "nginx-${NGINX_VERSION}/objs/lib"
