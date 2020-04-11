#!/bin/bash

sudo docker build . -t re_noob3 
sudo docker run --rm -dit -p 5001:5001 re_noob3
