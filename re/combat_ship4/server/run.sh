#!/bin/bash

sudo docker build . -t re_noob4
sudo docker run --rm -dit -p 5002:5002 re_noob4
