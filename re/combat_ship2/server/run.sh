#!/bin/bash

sudo docker build . -t re_noob2 
sudo docker run --rm -dit -p 5000:5000 re_noob2
