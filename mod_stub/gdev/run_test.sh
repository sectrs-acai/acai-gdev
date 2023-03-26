#!/bin/sh

./load_driver.sh
cd ./madd
LD_LIBRARY_PATH=/mnt/host/assets/snapshots/aarch64-lib/ ./user_test

