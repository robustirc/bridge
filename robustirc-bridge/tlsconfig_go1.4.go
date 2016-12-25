// +build go1.4

package main

import (
	"crypto/tls"

	"github.com/robustirc/bridge/tlsutil"
)

func makeTlsConfig() (*tls.Config, error) {
	kpr, err := tlsutil.NewKeypairReloader(*tlsCertPath, *tlsKeyPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		GetCertificate: kpr.GetCertificateFunc(),
	}, nil
}
