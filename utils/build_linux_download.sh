#!/bin/bash

source "$(dirname -- "${BASH_SOURCE[0]}")/build_common.sh"

download_nginx
download_libraries .

# make sure you have "Development Tools" and "Development Libraries" intalled for your distribution 

# Debian 
# sudo apt-get install build-essential

# Fedora 
# sudo dnf groupinstall "Development Tools" "Development Libraries"
