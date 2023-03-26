#!/bin/bash
#set -euo pipefail

CUR_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# source $CUR_DIR/../../../env.sh

TARGET=$CUR_DIR/build
rm -rf $TARGET
cmake -H. -B$TARGET -Ddriver=nouveau \
                    -Duser=ON \
                    -Druntime=OFF \
                    -Dusched=OFF \
                    -Duse_as=OFF \
                    -DCMAKE_BUILD_TYPE=Release
make -C $TARGET
make -C $TARGET install

#TARGET=$CUR_DIR/build
#mkdir -p $CUR_DIR/build/install
#rm -rf $TARGET
#cmake  -DCMAKE_INSTALL_PREFIX=$CUR_DIR/build/install  -H. -B$TARGET \
#    -Ddriver=nouveau \
#    -Duser=ON \
#    -Druntime=OFF \
#    -Dusched=OFF \
#    -Duse_as=OFF \
#    -DCMAKE_BUILD_TYPE=Release
#make -C $TARGET
#make -C $TARGET install

#TOOLCHAIN_FILE=$OUTPUT_LINUX_HOST_DIR/host/share/buildroot/toolchainfile.cmake
#cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE   -H. -B$TARGET \
#    -Ddriver=nouveau \
#    -Duser=ON \
#    -Druntime=OFF \
#    -Dusched=OFF \
#    -Duse_as=OFF \
#    -DCMAKE_BUILD_TYPE=Release
#make -C $TARGET
#make -C $TARGET install
