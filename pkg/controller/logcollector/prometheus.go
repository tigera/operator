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

package logcollector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	promapi "github.com/prometheus/client_golang/api"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	// esDataFlowWarningKey is the status key for ES data flow checks.
	esDataFlowWarningKey = "es-data-flow"

	// esDataFlowInfoQuery checks if data was indexed in the last 5 minutes.
	esDataFlowInfoQuery = `sum(increase(elasticsearch_index_stats_indexing_index_total{index=~"tigera_secure_ee_.*"}[5m]))`

	// esDataFlowWarningQuery checks if data was indexed in the last 30 minutes.
	esDataFlowWarningQuery = `sum(increase(elasticsearch_index_stats_indexing_index_total{index=~"tigera_secure_ee_.*"}[30m]))`

	// esDataFlowCheckInterval is how often we re-check ES data flow.
	esDataFlowCheckInterval = 5 * time.Minute

	// serviceAccountTokenPath is the path to the pod's service account token.
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// PrometheusClient is an interface for querying Prometheus, allowing for mocking in tests.
type PrometheusClient interface {
	// QueryDataFlowing queries Prometheus to determine if data has been indexed into
	// Elasticsearch recently. The query parameter should be a PromQL query that returns
	// a scalar or vector result.
	QueryDataFlowing(ctx context.Context, query string) (bool, error)
}

type prometheusClient struct {
	api promv1.API
}

// bearerTokenTransport wraps an http.RoundTripper to inject a Bearer token header.
type bearerTokenTransport struct {
	token string
	base  http.RoundTripper
}

func (t *bearerTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// newPrometheusClient creates a Prometheus API client configured with TLS and bearer token
// authentication. The trusted bundle provides the CA certificates to verify the Prometheus
// server. The bearer token is read from the operator pod's service account.
func newPrometheusClient(trustedBundle certificatemanagement.TrustedBundle) (PrometheusClient, error) {
	pemData := trustedBundle.GetCertificatesPEM()
	log.Info("Creating Prometheus client", "bundlePEMBytes", len(pemData))

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("failed to parse certificates from trusted bundle (%d bytes)", len(pemData))
	}

	// Read the service account bearer token from the operator pod.
	tokenBytes, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	tlsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
		DisableKeepAlives: true,
	}

	address := fmt.Sprintf("https://%s.%s:%d",
		monitor.PrometheusServiceServiceName,
		common.TigeraPrometheusNamespace,
		monitor.PrometheusDefaultPort,
	)

	apiClient, err := promapi.NewClient(promapi.Config{
		Address: address,
		RoundTripper: &bearerTokenTransport{
			token: token,
			base:  tlsTransport,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus API client: %w", err)
	}

	return &prometheusClient{
		api: promv1.NewAPI(apiClient),
	}, nil
}

// QueryDataFlowing runs a PromQL query and returns true if the result is > 0.
func (p *prometheusClient) QueryDataFlowing(ctx context.Context, query string) (bool, error) {
	result, _, err := p.api.Query(ctx, query, time.Now())
	if err != nil {
		return false, fmt.Errorf("failed to query Prometheus: %w", err)
	}

	switch v := result.(type) {
	case model.Vector:
		if len(v) > 0 && float64(v[0].Value) > 0 {
			return true, nil
		}
		return false, nil
	case *model.Scalar:
		return float64(v.Value) > 0, nil
	default:
		return false, fmt.Errorf("unexpected Prometheus result type: %T", result)
	}
}
