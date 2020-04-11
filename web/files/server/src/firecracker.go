package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type FirecrackerBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type FirecrackerImage struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type FirecrackerVsock struct {
	HostID     string `json:"vsock_id"`
	GuestID    int64  `json:"guest_cid"`
	SocketPath string `json:"uds_path"`
}

type FirecrackerMachineConfig struct {
	CpuCount int64 `json:"vcpu_count"`
	MemSize  int64 `json:"mem_size_mib"`
	HT       bool  `json:"ht_enabled"`
}

type FirecrackerConfig struct {
	BootSource    FirecrackerBootSource    `json:"boot-source"`
	Drives        []FirecrackerImage       `json:"drives"`
	MachineConfig FirecrackerMachineConfig `json:"machine-config"`
	Vsock         FirecrackerVsock         `json:"vsock"`
}

type FirecrackerVM struct {
    RemoteHost string
	Key               string
	FirecrackerConfig string
	VirtioSocket      string
}

func vsockDial(vm FirecrackerVM, deadline time.Time) (conn net.Conn, err error, done bool) {
	done = false
	var count int
	tmp := make([]byte, 16, 16)
	connectString := "CONNECT 2000\n"

	conn, err = net.Dial("unix", vm.VirtioSocket)
	if err != nil {
		return
	}
	conn.SetDeadline(deadline)

	count, _ = conn.Write([]byte(connectString))
	if count == len(connectString) {
		count, err = conn.Read(tmp)
		if count == 0 {
			return
		} else {
			done = true
			return
		}
	}
	return
}

func backendRequest(key string, req *http.Request) (resp *http.Response, err error) {
	deadline := time.Now().Add(VSOCK_TIMEOUT)
	var transport http.Transport
	lkey := strings.ToLower(key)

	mutex.Lock()
	vm, ok := machines[lkey]
	mutex.Unlock()

	if !ok {
		err = errors.New(fmt.Sprintf("Failed to find MicroVM with key %s", lkey))
		return
	}

	transport.DialContext = func(_ context.Context, _ string, _ string) (conn net.Conn, err error) {
		var done bool
		iter := make([]byte, 30, 30)
		for k, _ := range iter {
			if time.Now().After(deadline) {
				err = errors.New("vsock: Connection timed out")
				return
			}
			conn, err, done = vsockDial(vm, deadline)
			if done {
				return
			}
			if (k + 1) < len(iter) {
				time.Sleep(time.Millisecond * 200)
			}
		}
		return
	}
	return transport.RoundTrip(req)
}

func createVM(vm FirecrackerVM) {
	timeout := createTimeout()

	var kernel FirecrackerBootSource
	kernel.KernelImagePath = "/hack/firecracker/vmlinux.bin"
	kernel.BootArgs = "console=ttyS0 random.trust_cpu=on reboot=k panic=1 pci=off"

	var rootfs FirecrackerImage
	rootfs.DriveID = "rootfs"
	rootfs.PathOnHost = "/hack/firecracker/rootfs.img"
	rootfs.IsRootDevice = true
	rootfs.IsReadOnly = true

	var vsock FirecrackerVsock
	vsock.HostID = "10"
	vsock.GuestID = 20
	vsock.SocketPath = vm.VirtioSocket

	var machineConfig FirecrackerMachineConfig
	machineConfig.CpuCount = 1
	machineConfig.MemSize = 48
	machineConfig.HT = false

	var config FirecrackerConfig
	config.BootSource = kernel
	config.Drives = make([]FirecrackerImage, 1, 1)
	config.Drives[0] = rootfs
	config.Vsock = vsock
	config.MachineConfig = machineConfig

	configData, err := json.Marshal(config)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile(vm.FirecrackerConfig, configData, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	cmd := exec.Command("/hack/firecracker/bin", "--no-api", "--config-file", vm.FirecrackerConfig)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	defer timeout.start(err == nil)
	defer timeout.handle(vm, cmd.Process.Pid)
	if err != nil {
		fmt.Println(err)
	}
}
