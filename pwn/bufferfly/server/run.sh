#!/bin/bash
docker build . -t bufferfly
docker run --rm -it -p 6002:6002 bufferfly
