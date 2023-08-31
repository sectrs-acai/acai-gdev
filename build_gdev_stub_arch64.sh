#!/bin/bash
set -euo pipefail
#
# this builds escape aware gdev stub driver for fvp
#

CUR_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $CUR_DIR/../../../scripts/env-aarch64.sh
MOD=$CUR_DIR/mod/gdev

cd $MOD
make all
make headers
ls -al | grep gdev_stub
cd ../headers
ls -al