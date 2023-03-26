#!/bin/bash
set -euo pipefail

CUR_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $CUR_DIR/../../../env.sh

TARGET=$CUR_DIR/build_global

cmake  -H. -B$TARGET \
    -Ddriver=nouveau \
    -Duser=ON \
    -Druntime=OFF \
    -Dusched=OFF \
    -Duse_as=OFF \
    -DCMAKE_BUILD_TYPE=Release
make -C $TARGET
sudo make -C $TARGET install

