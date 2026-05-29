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

package enterprise

import (
	"errors"
	"fmt"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/operator"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/monitor"
)

type installationExtension struct{}

func registerInstallation() {
	operator.RegisterInstallationExtension(&installationExtension{})
}

func (e *installationExtension) Prepare(p operator.InstallationPrep) (operator.Context, error) {
	ctx := operator.Context{
		Installation:       p.Installation,
		FelixConfiguration: p.FelixConfiguration,
		ClusterDomain:      p.ClusterDomain,
		TrustedBundle:      p.TrustedBundle,
	}
	if !p.Installation.Variant.IsEnterprise() {
		return ctx, nil
	}

	// Reject the unsupported zero reporter port. (Port value derivation stays in
	// the OSS controller; only validation moves here.)
	if p.FelixConfiguration.Spec.PrometheusReporterPort != nil && *p.FelixConfiguration.Spec.PrometheusReporterPort == 0 {
		return ctx, errors.New("felixConfiguration prometheusReporterPort=0 not supported")
	}

	nodePrometheusTLS, err := p.CertificateManager.GetOrCreateKeyPair(
		p.Client, render.NodePrometheusTLSServerSecret, common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.CalicoNodeMetricsService, common.CalicoNamespace, p.ClusterDomain))
	if err != nil {
		return ctx, fmt.Errorf("error creating node prometheus TLS certificate: %w", err)
	}
	if nodePrometheusTLS != nil {
		p.TrustedBundle.AddCertificates(nodePrometheusTLS)
	}
	ctx.NodePrometheusTLS = nodePrometheusTLS

	prometheusClientCert, err := p.CertificateManager.GetCertificate(p.Client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return ctx, fmt.Errorf("unable to fetch prometheus certificate: %w", err)
	}
	if prometheusClientCert != nil {
		p.TrustedBundle.AddCertificates(prometheusClientCert)
	}

	esgwCertificate, err := p.CertificateManager.GetCertificate(p.Client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
	if err != nil {
		return ctx, fmt.Errorf("failed to retrieve / validate %s: %w", relasticsearch.PublicCertSecret, err)
	}
	if esgwCertificate != nil {
		p.TrustedBundle.AddCertificates(esgwCertificate)
	}

	return ctx, nil
}
