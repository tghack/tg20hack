#!/bin/bash

set -eux

rm -rf build
mkdir build
cd build
cmake ..
make -j8
