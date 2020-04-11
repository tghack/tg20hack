#!/bin/bash

set -eux
./build.sh

docker run --cap-add=SYS_PTRACE -p 6006:6006 --rm -it --name parallel2 tghack/parallel2
