#!/bin/bash

set -eux
cd ../
docker build -f server/Dockerfile -t tghack/parallel2 .
