//go:build !windows
// +build !windows

package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// nfds returns the number of listening file descriptors as passed by systemd
// when this application is started using systemd socket activation.
func nfds() int {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return 0
	}

	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil {
		return 0
	}
	return n
}

// handleSocketActivation handles listening on the systemd-provided sockets.
// It can return an error to differentiate between this implementation and
// the no-op on Windows.
func handleSocketActivation(n int) error {
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")

	p := newBridge(*network)

	const listenFdsStart = 3 // SD_LISTEN_FDS_START
	for fd := listenFdsStart; fd < listenFdsStart+n; fd++ {
		syscall.CloseOnExec(fd)
		name := "LISTEN_FD_" + strconv.Itoa(fd)
		offset := fd - listenFdsStart
		if offset < len(names) && len(names[offset]) > 0 {
			name = names[offset]
		}
		log.Printf("RobustIRC IRC bridge listening on file descriptor %d (%s)", fd, name)
		f := os.NewFile(uintptr(fd), name)
		ln, err := net.FileListener(f)
		if err != nil {
			log.Fatal(err)
		}
		f.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("Could not accept IRC client connection: %v\n", err)
					// Avoid flooding the logs with failed Accept()s.
					time.Sleep(1 * time.Second)
					continue
				}
				go p.handleIRC(conn)
			}
		}()
	}
	return nil
}
