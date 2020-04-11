package main

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
)

var counter int64 = 0
var mutex sync.Mutex
var counterMutex sync.Mutex

var machines = make(map[string]FirecrackerVM)
var remotes = make(map[string]string)

func validate(key string) bool {
	lkey := strings.ToLower(key)
	mutex.Lock()
	_, ok := machines[lkey]
	mutex.Unlock()

	return ok
}

func create(remote string) string {
    counterMutex.Lock()
	counter++
	id := strconv.FormatInt(counter, 10)
    name, ok := remotes[remote]
	counterMutex.Unlock()

    if ok {
        return name
    }

	keyBytes := make([]byte, 32, 32)
	rand.Read(keyBytes)

	var vm FirecrackerVM
	vm.FirecrackerConfig = "/hack/firecracker/config/f" + id + ".cfg"
	vm.VirtioSocket = "/hack/firecracker/sockets/s" + id + ".sock"
	vm.Key = strings.ToLower(hex.EncodeToString(keyBytes))
    vm.RemoteHost = remote

	createVM(vm)

	mutex.Lock()
	machines[vm.Key] = vm
    remotes[remote] = vm.Key
	mutex.Unlock()
	return vm.Key
}
