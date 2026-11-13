#!/bin/bash

source "$(dirname -- "${BASH_SOURCE[0]}")/build_common.sh"

echo "Run these commands manually after configuring:"
echo "1. Open the x64 Native Tools Command Prompt for Visual Studio 2022"
echo "2. cd nginx-${NGINX_VERSION}"
echo "3. nmake /f objs/Makefile"
