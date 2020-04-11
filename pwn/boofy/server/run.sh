#!/bin/bash
docker build . -t boofy
docker run --rm -it -p 6003:6003 boofy
