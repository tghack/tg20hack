#!/usr/bin/env bash
dir=$(dirname $(realpath $0))

docker stop ssti
docker rm ssti

docker build -t ssti ${dir}
docker run --device='/dev/kvm:/dev/kvm:rw' --name ssti -p 4005:4005 -it ssti
