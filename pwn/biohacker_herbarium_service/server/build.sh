#!/bin/bash

set -eux
cd ..
docker build -f server/Dockerfile -t tg20hack/plants .
