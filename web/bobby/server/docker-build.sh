#!/bin/bash

mkdir -p /go

GOPATH=/go

export GOPATH

go get github.com/mattn/go-sqlite3

go build -o /server/start /server/*.go
