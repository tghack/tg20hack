#!/usr/bin/env bash
docker build -t zero .
docker run -p '127.0.0.1:4002:4002' -it zero
