//go:build !go1.4
// +build !go1.4

package main

import "crypto/tls"

func makeTlsConfig() (*tls.Config, error) {
	tlsconfig := &tls.Config{
		Certificates: make([]tls.Certificate, 1),
	}

	var err error
	tlsconfig.Certificates[0], err = tls.LoadX509KeyPair(*tlsCertPath, *tlsKeyPath)
	return tlsconfig, err
}
