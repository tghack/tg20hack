#!/usr/bin/env bash
dir=$(dirname $(realpath $0))
docker build -t doctrina ${dir}
docker run -p 7000:7000 -it doctrina
