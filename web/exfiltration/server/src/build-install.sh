#!/usr/bin/env bash
export DEBIAN_FRONTEND=noninteractive

apt-get --yes update
apt-get --yes upgrade
apt-get --yes install curl golang-go
curl --silent https://deb.nodesource.com/setup_12.x | bash
mv /etc/apt /hack/apt
go build -o /hack/start /hack/src/*.go
rm /hack/src/*.go
