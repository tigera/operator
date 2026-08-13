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

package csr

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/monitor"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/extensions"
	rmonitor "github.com/tigera/operator/pkg/render/monitor"
)

// Extension is the Calico Enterprise behavior for the CSR controller.
type Extension struct{}

var _ extensions.CSRExtension = &Extension{}

// New returns the CSR extension.
func New() *Extension {
	return &Extension{}
}

// AllowedAssets adds the Prometheus server certificate to the signable set.
func (e *Extension) AllowedAssets(clusterDomain string) map[string]extensions.TLSAsset {
	return map[string]extensions.TLSAsset{
		rmonitor.PrometheusServerTLSSecretName: {
			ServiceAccountName:      rmonitor.PrometheusServiceAccountName,
			ServiceAccountNamespace: rmonitor.TigeraPrometheusObjectName,
			ValidDNSNames:           monitor.PrometheusTLSServerDNSNames(clusterDomain),
		},
	}
}

// NeedsCSRRole reports whether external Prometheus or a non-cluster host is configured.
// Both submit signing requests.
func (e *Extension) NeedsCSRRole(ctx context.Context, c client.Client) (bool, error) {
	monitorCR := &operatorv1.Monitor{}
	if err := c.Get(ctx, utils.DefaultEnterpriseInstanceKey, monitorCR); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, err
		}
	} else if monitorCR.Spec.ExternalPrometheus != nil {
		return true, nil
	}

	// Non-cluster hosts generate CSRs to establish mTLS connections with the cluster.
	nonclusterhost, err := utils.GetNonClusterHost(ctx, c)
	if err != nil {
		return false, err
	}
	return nonclusterhost != nil, nil
}

// Watches registers the Monitor CR, which decides whether the CSR role is needed.
func (e *Extension) Watches(c ctrlruntime.Controller) error {
	if err := c.WatchObject(&operatorv1.Monitor{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("csr-controller failed to watch Monitor: %w", err)
	}
	return nil
}
