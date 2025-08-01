#!/bin/bash

set -ex
set -o pipefail

rm -rf build
mkdir -p build
cd build

pwd

export INSATLL_DIR=${HOME}/workplace/local-install
export CTEST_OUTPUT_ON_FAILURE=1

NPROC=$(nproc)

mkdir -p ${INSATLL_DIR}
cmake \
    -DFIPS=0 \
    -DBUILD_SHARED_LIBS=0 \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_PREFIX_PATH=${INSATLL_DIR} \
    -DCMAKE_INSTALL_PREFIX=${INSATLL_DIR} \
    -DCMAKE_VERBOSE_MAKEFILE=1 \
    -DENABLE_DILITHIUM=ON \
    ..

make -j $NPROC 2>&1 | tee build_debug_output.txt
#ctest -j $NPROC | tee test_debug_output.txt
make install -j $NPROC