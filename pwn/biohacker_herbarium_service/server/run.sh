#!/bin/bash

docker run --rm -d --pids-limit 100 -p 6004:6004 --name plants tg20hack:plants
