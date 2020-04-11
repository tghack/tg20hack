#!/bin/bash
docker build . -t shellcoding
docker run --rm -it -p 1111:1111 --name shellcoding shellcoding
