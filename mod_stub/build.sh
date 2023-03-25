#!/bin/bash
set -euo pipefail
set -x
CUR_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $CUR_DIR/../../../../env.sh
TARGET=$CUR_DIR/release
TOOLCHAIN_FILE=$OUTPUT_LINUX_CCA_GUEST_DIR/host/share/buildroot/toolchainfile.cmake
cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE -DCMAKE_INSTALL_PREFIX=$CUR_DIR/install  -H. -B$TARGET \
    -DCMAKE_BUILD_TYPE=Release

#-Ddriver=nouveau \
#    -Duser=ON \
#    -Druntime=OFF \
#    -Dusched=OFF \
#    -Duse_as=OFF \
