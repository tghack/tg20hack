#!/usr/bin/env bash
dir=$(dirname $(realpath $0))
docker build -t shop ${dir}
docker run -p 4004:4004 -it shop
