#!/usr/bin/env bash
dir=$(dirname $(realpath $0))
docker build -t exfiltration ${dir}
docker run -p 4001:4001 -it exfiltration
