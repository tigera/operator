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
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/monitor"
)

// controllerExtension is the Calico Enterprise controller-side hook for the
// installation controller.
type controllerExtension struct{}

// Validate rejects installation config Calico Enterprise does not support.
func (controllerExtension) Validate(cc extensions.ControllerContext) error {
	// Reject the unsupported zero reporter port. The port value itself is derived
	// in the node modifier; only this validation lives here.
	if cc.FelixConfiguration.Spec.PrometheusReporterPort != nil && *cc.FelixConfiguration.Spec.PrometheusReporterPort == 0 {
		return errors.New("felixConfiguration prometheusReporterPort=0 not supported")
	}
	return nil
}

// ExtendContext does the controller-side work the modifiers can't: creating and
// fetching the certificates that feed the trusted bundle, returning the render
// context with the produced node prometheus keypair layered on.
func (controllerExtension) ExtendContext(cc extensions.ControllerContext) (extensions.RenderContext, error) {
	rc := cc.RenderContext

	nodePrometheusTLS, err := cc.CertificateManager.GetOrCreateKeyPair(
		cc.Client,
		render.NodePrometheusTLSServerSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.CalicoNodeMetricsService, common.CalicoNamespace, cc.ClusterDomain),
	)
	if err != nil {
		return rc, fmt.Errorf("error creating node prometheus TLS certificate: %w", err)
	}
	if nodePrometheusTLS != nil {
		cc.TrustedBundle.AddCertificates(nodePrometheusTLS)
	}
	rc.NodePrometheusTLS = nodePrometheusTLS

	prometheusClientCert, err := cc.CertificateManager.GetCertificate(cc.Client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return rc, fmt.Errorf("unable to fetch prometheus certificate: %w", err)
	}
	if prometheusClientCert != nil {
		cc.TrustedBundle.AddCertificates(prometheusClientCert)
	}

	esgwCertificate, err := cc.CertificateManager.GetCertificate(cc.Client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
	if err != nil {
		return rc, fmt.Errorf("failed to retrieve / validate %s: %w", relasticsearch.PublicCertSecret, err)
	}
	if esgwCertificate != nil {
		cc.TrustedBundle.AddCertificates(esgwCertificate)
	}

	return rc, nil
}
