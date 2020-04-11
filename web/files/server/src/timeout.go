package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

type FirecrackerTimeout chan bool

func createTimeout() FirecrackerTimeout {
	return make(FirecrackerTimeout)
}

func (ch FirecrackerTimeout) start(alive bool) {
	go func() {
		if alive {
			time.Sleep(FIRECRACKER_TIMEOUT)
		}
		ch <- alive
	}()
}

func (ch FirecrackerTimeout) handle(vm FirecrackerVM, pid int) {
	go func() {
		alive := <-ch

		mutex.Lock()
		delete(machines, vm.Key)
		delete(remotes, vm.RemoteHost)
		mutex.Unlock()

		if alive {
			process, err := os.FindProcess(pid)
			if err == nil {
				process.Signal(unix.SIGTERM)
			}
		}

		err := os.Remove(vm.VirtioSocket)
		if err != nil {
			fmt.Println(err)
		}
		err = os.Remove(vm.FirecrackerConfig)
		if err != nil {
			fmt.Println(err)
		}
	}()
}
