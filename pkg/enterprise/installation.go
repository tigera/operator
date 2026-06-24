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
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/contexts"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
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

	// kubeControllerTLS is the calico-kube-controllers metrics serving keypair; the
	// kube-controllers modifier mounts it onto the deployment.
	kubeControllerTLS certificatemanagement.KeyPairInterface

	// collectProcessPath mirrors LogCollector.Spec.CollectProcessPath being
	// enabled; the node modifier uses it to set HostPID and the felix env.
	collectProcessPath bool

	// calico-kube-controllers enterprise additions the kube-controllers modifier
	// applies: the enterprise cluster role rules, the enterprise enabled controllers,
	// and the WAF v3 (Gateway API add-on) surface.
	kubeControllerRules       []rbacv1.PolicyRule
	kubeControllerControllers []string
	waf                       wafRenderData
}

// installationData pulls the installation extension's render data back out of the
// render context, returning the zero value when none is set.
func installationData(rc render.RenderContext) installationRenderData {
	return render.ExtractExtensionData[installationRenderData](rc)
}

func collectProcessPathEnabled(lc *operatorv1.LogCollector) bool {
	return lc != nil &&
		lc.Spec.CollectProcessPath != nil &&
		*lc.Spec.CollectProcessPath == operatorv1.CollectProcessPathEnable
}

// Validate rejects installation config Calico Enterprise does not support.
func (coreControllerExtension) Validate(cc contexts.ControllerContext) error {
	return validateReporterPort(cc.FelixConfiguration)
}

// DefaultFelixConfiguration sets the Enterprise-only FelixConfiguration defaults.
// Some platforms run a DNS service that isn't named "kube-dns", so dnsTrustedServers
// needs a provider-specific default for Enterprise DNS logging to work. Returns
// whether it changed fc.
func (coreControllerExtension) DefaultFelixConfiguration(install *operatorv1.InstallationSpec, fc *v3.FelixConfiguration) (bool, error) {
	dnsService := ""
	switch install.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		dnsService = "k8s-service:openshift-dns/dns-default"
	case operatorv1.ProviderRKE2:
		dnsService = "k8s-service:kube-system/rke2-coredns-rke2-coredns"
	}
	if dnsService == "" {
		return false, nil
	}

	felixDefault := "k8s-service:kube-dns"
	trustedServers := []string{dnsService}
	// Keep any other values that are already configured, excepting the value we are
	// setting and the kube-dns default.
	existingSetting := ""
	if fc.Spec.DNSTrustedServers != nil {
		existingSetting = strings.Join(*fc.Spec.DNSTrustedServers, ",")
		for _, server := range *fc.Spec.DNSTrustedServers {
			if server != felixDefault && server != dnsService {
				trustedServers = append(trustedServers, server)
			}
		}
	}
	if strings.Join(trustedServers, ",") == existingSetting {
		return false, nil
	}
	fc.Spec.DNSTrustedServers = &trustedServers
	return true, nil
}

// Watches registers the enterprise resources the installation controller
// reconciles on.
func (coreControllerExtension) Watches(c ctrlruntime.Controller) error {
	for _, obj := range []client.Object{
		&operatorv1.ManagementCluster{},
		&operatorv1.ManagementClusterConnection{},
		&operatorv1.LogCollector{},
		// GatewayAPI.spec.extensions.waf.state gates the WAF v3 surface on calico-kube-controllers.
		&operatorv1.GatewayAPI{},
	} {
		if err := c.WatchObject(obj, &handler.EnqueueRequestForObject{}); err != nil {
			return err
		}
	}
	// es-kube-controllers includes the manager internal TLS secret in its bundle.
	return utils.AddSecretsWatch(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
}

// ExtendContext does the controller-side work the modifiers can't: creating and
// fetching the certificates that feed the trusted bundle. It returns the render
// context carrying the produced node prometheus keypair, and that keypair as one
// the controller should manage.
func (coreControllerExtension) ExtendContext(cc contexts.ControllerContext) (render.RenderContext, []certificatemanagement.KeyPairInterface, error) {
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

	// The calico-kube-controllers metrics endpoint is served with mTLS in
	// Enterprise; the keypair is created here (cluster side effect) and mounted by
	// the kube-controllers modifier.
	kubeControllerTLS, err := cc.CertificateManager.GetOrCreateKeyPair(
		cc.Client,
		kubecontrollers.KubeControllerPrometheusTLSSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, cc.ClusterDomain),
	)
	if err != nil {
		return rc, nil, fmt.Errorf("error creating kube-controllers metrics TLS certificate: %w", err)
	}
	if kubeControllerTLS != nil {
		cc.TrustedBundle.AddCertificates(kubeControllerTLS)
	}

	logCollector, err := utils.GetLogCollector(cc.Ctx, cc.Client)
	if err != nil {
		return rc, nil, fmt.Errorf("error reading LogCollector: %w", err)
	}

	// calico-kube-controllers enterprise additions: the WAF surface, the enterprise
	// cluster role rules, and the enterprise enabled controllers. A managed cluster's
	// kube-controllers needs an extra license-push rule.
	managementClusterConnection, err := utils.GetManagementClusterConnection(cc.Ctx, cc.Client)
	if err != nil {
		return rc, nil, fmt.Errorf("error reading ManagementClusterConnection: %w", err)
	}
	waf, wafWebhookTLS, err := buildWAFData(cc)
	if err != nil {
		return rc, nil, fmt.Errorf("error preparing WAF configuration: %w", err)
	}

	rc.Extension = installationRenderData{
		nodePrometheusTLS:         nodePrometheusTLS,
		kubeControllerTLS:         kubeControllerTLS,
		collectProcessPath:        collectProcessPathEnabled(logCollector),
		kubeControllerRules:       calicoKubeControllersEnterpriseRules(waf.enabled, managementClusterConnection != nil),
		kubeControllerControllers: calicoKubeControllersEnterpriseControllers(waf.enabled),
		waf:                       waf,
	}

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

	// es-kube-controllers talks to Voltron, so the shared bundle must trust the
	// manager internal cert.
	managerInternalTLS, err := cc.CertificateManager.GetCertificate(cc.Client, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return rc, nil, fmt.Errorf("failed to retrieve %s: %w", render.ManagerInternalTLSSecretName, err)
	}
	if managerInternalTLS != nil {
		cc.TrustedBundle.AddCertificates(managerInternalTLS)
	}

	var managed []certificatemanagement.KeyPairInterface
	if nodePrometheusTLS != nil {
		managed = append(managed, nodePrometheusTLS)
	}
	if kubeControllerTLS != nil {
		managed = append(managed, kubeControllerTLS)
	}
	if wafWebhookTLS != nil {
		managed = append(managed, wafWebhookTLS)
	}
	return rc, managed, nil
}
