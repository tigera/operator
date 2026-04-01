// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/tigera/operator/pkg/common"
)

const (
	// Default file paths for TLS certificates, projected via Kubernetes volume mounts.
	defaultMetricsTLSCertFile = "/etc/tigera-operator-tls/tls.crt"
	defaultMetricsTLSKeyFile  = "/etc/tigera-operator-tls/tls.key"
	defaultMetricsTLSCAFile   = "/etc/tigera-ca-private/tls.crt"
)

// metricsAddr returns the bind address for the metrics endpoint.
// When METRICS_ENABLED is not "true", returns "0" to disable metrics.
// Otherwise, defaults to 0.0.0.0:9484 and allows overriding via
// METRICS_HOST and METRICS_PORT.
func metricsAddr() string {
	if !common.MetricsEnabled() {
		// the controller-runtime accepts '0' to denote that metrics should be disabled.
		return "0"
	}

	metricsHost := os.Getenv("METRICS_HOST")
	if metricsHost == "" {
		metricsHost = "0.0.0.0"
	}

	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		return fmt.Sprintf("%s:%d", metricsHost, defaultMetricsPort)
	}

	return fmt.Sprintf("%s:%s", metricsHost, metricsPort)
}

// ParseTLSVersion parses TLS version string and returns the corresponding tls version constant.
// Accepts: "1.2", "1.3", or empty string (defaults to "1.2").
func ParseTLSVersion(version string) (uint16, error) {
	switch version {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s (supported versions: 1.2, 1.3)", version)
	}
}

// metricsClientAuth returns the tls.ClientAuthType based on the METRICS_CLIENT_AUTH env var.
// Default is RequireAndVerifyClientCert.
func metricsClientAuth() tls.ClientAuthType {
	switch strings.ToLower(os.Getenv("METRICS_CLIENT_AUTH")) {
	case "requireanyclientcert":
		return tls.RequireAnyClientCert
	case "verifyclientcertifgiven":
		return tls.VerifyClientCertIfGiven
	case "noclientcert":
		return tls.NoClientCert
	default:
		return tls.RequireAndVerifyClientCert
	}
}

// metricsTLSCertFile returns the path to the TLS certificate file for the metrics endpoint.
func metricsTLSCertFile() string {
	if v := os.Getenv("METRICS_TLS_CERT_FILE"); v != "" {
		return v
	}
	return defaultMetricsTLSCertFile
}

// metricsTLSKeyFile returns the path to the TLS key file for the metrics endpoint.
func metricsTLSKeyFile() string {
	if v := os.Getenv("METRICS_TLS_KEY_FILE"); v != "" {
		return v
	}
	return defaultMetricsTLSKeyFile
}

// metricsTLSCAFile returns the path to the CA certificate file for client verification.
func metricsTLSCAFile() string {
	if v := os.Getenv("METRICS_TLS_CA_FILE"); v != "" {
		return v
	}
	return defaultMetricsTLSCAFile
}

// getCertificateFromFile returns a GetCertificate callback that loads the cert from
// disk on each TLS handshake. Kubelet automatically updates projected secret volumes,
// so rotations are picked up without restart or polling.
func getCertificateFromFile(certFile, keyFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load metrics TLS keypair: %w", err)
		}
		return &cert, nil
	}
}

// loadClientCAFromFile reads a PEM CA certificate file and returns an x509.CertPool.
// Returns an empty pool if the file doesn't exist yet (optional volume mount).
func loadClientCAFromFile(caFile string) *x509.CertPool {
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return pool
	}
	pool.AppendCertsFromPEM(caPEM)
	return pool
}
