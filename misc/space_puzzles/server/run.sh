#!/bin/bash

sudo docker build . -t space_puzzle 
sudo docker kill space_puzzle
sudo docker run --rm -dit --net=dockernet -p 7002:7002 --name space_puzzle space_puzzle
