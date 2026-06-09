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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/monitor"
)

func registerInstallation() {
	extensions.RegisterSetup(operatorv1.CalicoEnterprise, setup)
}

// setup is the Calico Enterprise setup phase. It builds the base render context
// and then does the controller-side work the modifiers can't: validating config
// and creating/fetching the certificates that feed the trusted bundle.
func setup(in extensions.Inputs) (extensions.RenderContext, error) {
	rc := extensions.BaseRenderContext(in)

	// Reject the unsupported zero reporter port. The port value itself is derived
	// in the node modifier; only this validation lives here.
	if in.FelixConfiguration.Spec.PrometheusReporterPort != nil && *in.FelixConfiguration.Spec.PrometheusReporterPort == 0 {
		return rc, errors.New("felixConfiguration prometheusReporterPort=0 not supported")
	}

	nodePrometheusTLS, err := in.CertificateManager.GetOrCreateKeyPair(
		in.Client,
		render.NodePrometheusTLSServerSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.CalicoNodeMetricsService, common.CalicoNamespace, in.ClusterDomain),
	)
	if err != nil {
		return rc, fmt.Errorf("error creating node prometheus TLS certificate: %w", err)
	}
	if nodePrometheusTLS != nil {
		in.TrustedBundle.AddCertificates(nodePrometheusTLS)
	}
	rc.NodePrometheusTLS = nodePrometheusTLS

	prometheusClientCert, err := in.CertificateManager.GetCertificate(in.Client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return rc, fmt.Errorf("unable to fetch prometheus certificate: %w", err)
	}
	if prometheusClientCert != nil {
		in.TrustedBundle.AddCertificates(prometheusClientCert)
	}

	esgwCertificate, err := in.CertificateManager.GetCertificate(in.Client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
	if err != nil {
		return rc, fmt.Errorf("failed to retrieve / validate %s: %w", relasticsearch.PublicCertSecret, err)
	}
	if esgwCertificate != nil {
		in.TrustedBundle.AddCertificates(esgwCertificate)
	}

	return rc, nil
}
