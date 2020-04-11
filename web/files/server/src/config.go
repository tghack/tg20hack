package main

import "time"

const HTTP_PORT = 4005

const MAX_BODY_SIZE = 98304 // 96 KB

const CHALLENGE_FLAG = "TG20{skilled_statistic_unhappily_icing}"

const FIRECRACKER_TIMEOUT time.Duration = (time.Minute * 10)

const VSOCK_TIMEOUT time.Duration = (time.Second * 10)
