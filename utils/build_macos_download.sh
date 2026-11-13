#!/bin/bash

source "$(dirname -- "${BASH_SOURCE[0]}")/build_common.sh"

download_nginx
download_libraries .
