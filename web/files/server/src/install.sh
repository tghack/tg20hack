#!/usr/bin/env bash
mkdir -p '/hack/firecracker/sockets'
mkdir -p '/hack/firecracker/config'
mkdir -p '/hack/gopath'
mv '/hack/src/restart.html' '/hack/restart.html'

export GOPATH=/hack/gopath

latest=$(basename $(curl --silent --output /dev/null --write-out  '%{redirect_url}'  'https://github.com/firecracker-microvm/firecracker/releases/latest'))
curl --silent --location --output '/hack/firecracker/bin' "https://github.com/firecracker-microvm/firecracker/releases/download/${latest}/firecracker-${latest}-x86_64"

latest=$(basename $(curl --silent --output /dev/null --write-out  '%{redirect_url}'  'https://github.com/roypur/firecracker-kernel/releases/latest'))
curl --silent --location --output '/hack/firecracker/vmlinux.bin' "https://github.com/roypur/firecracker-kernel/releases/download/${latest}/vmlinux.bin"

chmod -R 755 /hack/firecracker

go get 'golang.org/x/sys/unix'

go build -o '/hack/start' \
    '/hack/src/main.go' \
    '/hack/src/firecracker.go' \
    '/hack/src/storage.go' \
    '/hack/src/timeout.go' \
    '/hack/src/config.go'

rm -rf '/hack/src'
rm -rf '/hack/gopath'
