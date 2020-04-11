#!/bin/bash

docker run --rm -it --workdir=/opt --net=dockernet --name nonograms -v $PWD:/opt/src tg20hack/nonograms
