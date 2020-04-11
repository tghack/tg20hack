#!/usr/bin/env bash
export DEBIAN_FRONTEND=noninteractive

useradd hack
apt-get --yes update
apt-get --yes upgrade
apt-get --yes install ca-certificates

rm -rf /etc/apt
mv /hack/apt /etc/apt
apt-get --yes update
apt-get --yes upgrade

apt-get --yes install nodejs tini chromium
npm install puppeteer --global --unsafe-perm=true
