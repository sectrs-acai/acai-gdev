#!/bin/bash
set -euo pipefail

CUR_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $CUR_DIR/../../../scripts/env-aarch64.sh
MOD=$CUR_DIR/mod_stub/gdev

cd $MOD
# make clean
make all
make headers
ls -al | grep gdev_stub
cd ../headers
ls -al