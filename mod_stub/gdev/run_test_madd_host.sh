#!/bin/sh

./load_driver.sh
cd ./cuda_test/madd_host
LD_LIBRARY_PATH=/mnt/host/assets/snapshots/aarch64-lib/ ./user_test

