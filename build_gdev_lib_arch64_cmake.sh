#!/bin/bash
#
# deprecated: use buildroot gdev-guest package recepie to build
#
set -euo pipefail

CUR_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $CUR_DIR/../../../scripts/env-aarch64.sh
SRC=$CUR_DIR/lib/kernel/

set -x
cd $SRC
make clean
make all
ls -al
ln -s libgdev.so.1.0.0 libgdev.so || true
ln -s libgdev.so.1.0.0 libgdev.so.1 || true
ln -s --relative . lib64 || true

# copies assets to snapshot dir
mkdir -p $ASSETS_DIR/snapshots/aarch64-lib || true
cp -rf $SRC/*so* $ASSETS_DIR/snapshots/aarch64-lib || true
ls -al $ASSETS_DIR/snapshots/aarch64-lib || true



SRC_CUDA=$CUR_DIR/cuda
cd $SRC_CUDA

source $CUR_DIR/../../../env.sh

TARGET=$CUR_DIR/build_cmake
# rm -rf $TARGET

cmake  -H. -B$TARGET \
    -Ddriver=nouveau \
    -Duser=ON \
    -Druntime=ON \
    -Dusched=OFF \
    -Duse_as=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -Dgdev_dir=$SRC
make -C $TARGET
## copies assets to snapshot dir

cp -rf $TARGET/*so* $ASSETS_DIR/snapshots/aarch64-lib || true
ls -al $ASSETS_DIR/snapshots/aarch64-lib || true