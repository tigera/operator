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
	"fmt"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// coreControllerExtension is the Calico Enterprise controller-side hook for the
// installation controller.
type coreControllerExtension struct{}

// installationRenderData is the controller-produced data the installation
// extension hands to its modifiers through RenderContext.Extension. The node
// modifier type-asserts it back out.
type installationRenderData struct {
	nodePrometheusTLS certificatemanagement.KeyPairInterface
}

// installationData pulls the installation extension's render data back out of the
// render context, returning the zero value when none is set.
func installationData(rc extensions.RenderContext) installationRenderData {
	data, _ := rc.Extension.(installationRenderData)
	return data
}

// Validate rejects installation config Calico Enterprise does not support.
func (coreControllerExtension) Validate(cc extensions.ControllerContext) error {
	return validateReporterPort(cc.FelixConfiguration)
}

// ExtendContext does the controller-side work the modifiers can't: creating and
// fetching the certificates that feed the trusted bundle. It returns the render
// context carrying the produced node prometheus keypair, and that keypair as one
// the controller should manage.
func (coreControllerExtension) ExtendContext(cc extensions.ControllerContext) (extensions.RenderContext, []certificatemanagement.KeyPairInterface, error) {
	rc := cc.RenderContext

	nodePrometheusTLS, err := cc.CertificateManager.GetOrCreateKeyPair(
		cc.Client,
		render.NodePrometheusTLSServerSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.CalicoNodeMetricsService, common.CalicoNamespace, cc.ClusterDomain),
	)
	if err != nil {
		return rc, nil, fmt.Errorf("error creating node prometheus TLS certificate: %w", err)
	}
	if nodePrometheusTLS != nil {
		cc.TrustedBundle.AddCertificates(nodePrometheusTLS)
	}
	rc.Extension = installationRenderData{nodePrometheusTLS: nodePrometheusTLS}

	prometheusClientCert, err := cc.CertificateManager.GetCertificate(cc.Client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return rc, nil, fmt.Errorf("unable to fetch prometheus certificate: %w", err)
	}
	if prometheusClientCert != nil {
		cc.TrustedBundle.AddCertificates(prometheusClientCert)
	}

	esgwCertificate, err := cc.CertificateManager.GetCertificate(cc.Client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
	if err != nil {
		return rc, nil, fmt.Errorf("failed to retrieve / validate %s: %w", relasticsearch.PublicCertSecret, err)
	}
	if esgwCertificate != nil {
		cc.TrustedBundle.AddCertificates(esgwCertificate)
	}

	var managed []certificatemanagement.KeyPairInterface
	if nodePrometheusTLS != nil {
		managed = append(managed, nodePrometheusTLS)
	}
	return rc, managed, nil
}
