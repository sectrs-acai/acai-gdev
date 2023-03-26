#!/bin/bash
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

mkdir -p $ASSETS_DIR/snapshots/aarch64-lib
cp -rf $SRC/*so* $ASSETS_DIR/snapshots/aarch64-lib

ls -al $ASSETS_DIR/snapshots/aarch64-lib



SRC_CUDA=$CUR_DIR/cuda
cd $SRC_CUDA
rm -rf build
mkdir build
cd build
../configure --disable-runtime
make
ln -s libucuda.so.1.0.0 libucuda.so || true
ln -s libucuda.so.1.0.0 libucuda.so.1 || true
cp -rf *so* $ASSETS_DIR/snapshots/aarch64-lib
ls -al $ASSETS_DIR/snapshots/aarch64-lib