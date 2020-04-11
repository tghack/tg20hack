#!/bin/bash
docker build . -t poke 
docker run --rm -it -p 6001:6001 poke 
