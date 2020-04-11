#!/bin/bash

set -eux

cp Dockerfile ..
cd ..
curl -O -L https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz
tar xvf glibc-2.31.tar.xz
rm glibc-2.31.tar.xz
docker build . -t tg20hack/crap
