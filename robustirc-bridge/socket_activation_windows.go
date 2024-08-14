//go:build windows
// +build windows

package main

import (
	"errors"
	"sync"
)

// nfds returns 0 to indicate that systemd socket activation is unsupported on Windows.
func nfds() int {
	return 0
}

// handleSocketActivation is no-op on Windows. It returns an error to be able terminate the program
// instead of sleeping indefinitely.
func handleSocketActivation(n int, connWG *sync.WaitGroup) error {
	return errors.New("systemd socket activation is not available on Windows")
}
