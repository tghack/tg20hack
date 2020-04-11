#!/usr/bin/env bash
dir=$(dirname $(realpath $0))
docker build -t bobby ${dir}
docker run -p 4000:4000 -it bobby
