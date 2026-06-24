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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/gatewayapi"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

// registerKubeControllers registers the calico-kube-controllers modifiers. There is
// no image override: kube-controllers runs from the combined calico image, which
// resolves by variant in the base render.
func registerKubeControllers(v *extensions.Variant) {
	v.Modify(render.ComponentNameKubeControllers, modifyKubeControllers)
	v.Modify(render.ComponentNameKubeControllersPolicy, modifyKubeControllersPolicy)
}

// modifyKubeControllersPolicy adds the WAF admission webhook ingress rule to the
// calico-kube-controllers calico-system network policy, so the kube-apiserver can
// reach the in-process webhook on :9443 (EV-6386). Without it the calico-system
// default-deny drops the apiserver->:9443 call and WAF admission times out.
func modifyKubeControllersPolicy(rc extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
	if !installationData(rc).waf.enabled {
		return objs, del
	}
	policy, ok := extensions.FindObject[*v3.NetworkPolicy](objs, kubecontrollers.KubeControllerNetworkPolicyName)
	if !ok {
		return objs, del
	}
	policy.Spec.Ingress = append(policy.Spec.Ingress, v3.Rule{
		Action:   v3.Allow,
		Protocol: &networkpolicy.TCPProtocol,
		Destination: v3.EntityRule{
			Ports: networkpolicy.Ports(uint16(applicationlayer.WAFWebhookContainerPort)),
		},
	})
	return objs, del
}

// modifyKubeControllers layers the full Calico Enterprise surface onto the rendered
// calico-kube-controllers objects: the enterprise cluster role rules, the enterprise
// enabled controllers, the metrics serving TLS, and the WAF v3 (Gateway API add-on)
// surface. The modifier only runs for the enterprise variant, so everything it adds
// is enterprise-only by construction - the base render carries none of it. The
// controller-side inputs (keypairs, the resolved wasm image, the pull secret) are
// produced by the installation hook and handed in through rc.
func modifyKubeControllers(rc extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
	data := installationData(rc)

	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole); ok {
		role.Rules = append(role.Rules, data.kubeControllerRules...)
	}

	if dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController); ok {
		modifyKubeControllersDeployment(rc, dp, data)
	}

	// The WAF admission webhook surface (Service + ValidatingWebhookConfiguration),
	// the wasm pull secret, and the wasm CA bundle. Created when WAF is enabled,
	// deleted otherwise so toggling the extension off cleans them up.
	webhookObjs := applicationlayer.WAFAdmissionWebhookComponents(data.waf.caBundle)
	if data.waf.enabled {
		objs = append(objs, webhookObjs...)
		if data.waf.pullSecret != nil {
			objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(common.CalicoNamespace, data.waf.pullSecret)...)...)
		}
		if data.waf.caCert != nil {
			objs = append(objs, data.waf.caCert)
		}
	} else {
		del = append(del, webhookObjs...)
	}

	return objs, del
}

func modifyKubeControllersDeployment(rc extensions.RenderContext, dp *appsv1.Deployment, data installationRenderData) {
	spec := &dp.Spec.Template.Spec
	if dp.Spec.Template.Annotations == nil {
		dp.Spec.Template.Annotations = map[string]string{}
	}

	if tls := data.kubeControllerTLS; tls != nil {
		spec.Volumes = append(spec.Volumes, tls.Volume())
		dp.Spec.Template.Annotations[tls.HashAnnotationKey()] = tls.HashAnnotationValue()
	}
	if waf := data.waf; waf.enabled && waf.webhookTLS != nil {
		spec.Volumes = append(spec.Volumes, waf.webhookTLS.Volume())
	}

	for i := range spec.Containers {
		c := &spec.Containers[i]
		if c.Name != kubecontrollers.KubeController {
			continue
		}

		appendEnabledControllers(c, data.kubeControllerControllers)
		c.Env = append(c.Env, enterpriseEnv(rc)...)

		if tls := data.kubeControllerTLS; tls != nil {
			c.Env = append(c.Env,
				corev1.EnvVar{Name: "TLS_KEY_PATH", Value: tls.VolumeMountKeyFilePath()},
				corev1.EnvVar{Name: "TLS_CRT_PATH", Value: tls.VolumeMountCertificateFilePath()},
				corev1.EnvVar{Name: "CLIENT_COMMON_NAME", Value: monitor.PrometheusClientTLSSecretName},
			)
			c.VolumeMounts = append(c.VolumeMounts, tls.VolumeMount(rmeta.OSTypeLinux))
			if tls.UseCertificateManagement() {
				spec.InitContainers = append(spec.InitContainers, tls.InitContainer(common.CalicoNamespace, c.SecurityContext))
			}
		}

		if waf := data.waf; waf.enabled {
			c.Env = append(c.Env, wafEnv(waf)...)
			c.Ports = append(c.Ports, corev1.ContainerPort{
				Name:          "waf-webhook",
				ContainerPort: applicationlayer.WAFWebhookContainerPort,
				Protocol:      corev1.ProtocolTCP,
			})
			if waf.webhookTLS != nil {
				c.VolumeMounts = append(c.VolumeMounts, waf.webhookTLS.VolumeMount(rmeta.OSTypeLinux))
				if waf.webhookTLS.UseCertificateManagement() {
					spec.InitContainers = append(spec.InitContainers, waf.webhookTLS.InitContainer(common.CalicoNamespace, c.SecurityContext))
				}
			}
		}
	}
}

// appendEnabledControllers folds the enterprise controllers into the existing
// ENABLED_CONTROLLERS env the base render set (node,loadbalancer).
func appendEnabledControllers(c *corev1.Container, extra []string) {
	if len(extra) == 0 {
		return
	}
	for i := range c.Env {
		if c.Env[i].Name == "ENABLED_CONTROLLERS" {
			c.Env[i].Value = c.Env[i].Value + "," + strings.Join(extra, ",")
			return
		}
	}
}

// enterpriseEnv is the static enterprise env for calico-kube-controllers. The
// modifier runs only for the enterprise variant, so these are never rendered for core.
func enterpriseEnv(rc extensions.RenderContext) []corev1.EnvVar {
	var env []corev1.EnvVar
	if rc.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: rc.TrustedBundle.MountPath()})
	}
	if in := rc.Installation; in != nil && in.CalicoNetwork != nil && in.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: in.CalicoNetwork.MultiInterfaceMode.Value()})
	}
	return env
}

// wafEnv is the WAF v3 env the kube-controllers binary consumes to program WAF policy
// attachments. WASM_IMAGE is the pre-resolved reference the hook produced.
func wafEnv(waf wafRenderData) []corev1.EnvVar {
	var env []corev1.EnvVar
	if waf.wasmImage != "" {
		env = append(env, corev1.EnvVar{Name: "WASM_IMAGE", Value: waf.wasmImage})
	}
	if waf.pullSecret != nil {
		env = append(env, corev1.EnvVar{Name: "WASM_PULL_SECRET", Value: waf.pullSecret.Name})
	}
	if waf.caCert != nil {
		env = append(env, corev1.EnvVar{Name: "WASM_CA_CERT", Value: waf.caCert.Name})
	}
	if waf.webhookTLS != nil {
		env = append(env, corev1.EnvVar{Name: "WAF_WEBHOOK_CERT_DIR", Value: filepath.Dir(waf.webhookTLS.VolumeMountCertificateFilePath())})
	}
	return env
}

const (
	EsKubeController                  = "es-calico-kube-controllers"
	EsKubeControllerRole              = "es-calico-kube-controllers"
	EsKubeControllerRoleBinding       = "es-calico-kube-controllers"
	EsKubeControllerMetrics           = "es-calico-kube-controllers-metrics"
	EsKubeControllerNetworkPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "es-kube-controller-access"

	ElasticsearchKubeControllersUserSecret             = "tigera-ee-kube-controllers-elasticsearch-access"
	ElasticsearchKubeControllersUserName               = "tigera-ee-kube-controllers"
	ElasticsearchKubeControllersSecureUserSecret       = "tigera-ee-kube-controllers-elasticsearch-access-gateway"
	ElasticsearchKubeControllersVerificationUserSecret = "tigera-ee-kube-controllers-gateway-verification-credentials"

	// WASMPullSecretName is the dedicated image-pull Secret (a merged copy of the
	// install pull secrets) the WAF reconciler replicates into tenant namespaces for
	// the Coraza wasm OCI pull. A dedicated name avoids clashing with the
	// operator-managed tigera-pull-secret the GatewayAPI render also copies there (EV-6386).
	WASMPullSecretName = "tigera-waf-pull-secret"

	// WASMCACertName is the dedicated CA-bundle ConfigMap the WAF reconciler
	// replicates into tenant namespaces for the Coraza wasm OCI registry TLS check -
	// a dedicated name avoids clashing with the operator-managed tigera-ca-bundle the
	// GatewayAPI render also copies there (EV-6386). It is a renamed copy of the trusted bundle.
	WASMCACertName = "tigera-waf-ca-bundle"
)

// NewElasticsearchKubeControllers fills the generic kube-controllers configuration
// for the enterprise es-calico-kube-controllers deployment and returns the rendered
// component. es-kube-controllers is a distinct deployment (talks to Elasticsearch via
// es-gateway) reconciled by the logstorage kube-controllers controller, so it's
// assembled here rather than through the render-time modifier mechanism.
func NewElasticsearchKubeControllers(cfg *kubecontrollers.KubeControllersConfiguration) render.Component {
	cfg.Name = EsKubeController
	cfg.ConfigName = "elasticsearch"
	cfg.RoleName = EsKubeControllerRole
	cfg.RoleBindingName = EsKubeControllerRoleBinding
	cfg.MetricsName = EsKubeControllerMetrics
	cfg.DisableConfigAPI = cfg.Tenant.MultiTenant()

	cfg.Rules = kubecontrollers.KubeControllersRoleCommonRules(cfg)
	cfg.Rules = append(cfg.Rules, kubeControllersEnterpriseCommonRules(false, cfg.ManagementClusterConnection != nil)...)
	cfg.Rules = append(cfg.Rules,
		rbacv1.PolicyRule{
			APIGroups: []string{"elasticsearch.k8s.elastic.co"},
			Resources: []string{"elasticsearches"},
			Verbs:     []string{"watch", "get", "list"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings"},
			Verbs:     []string{"watch", "list", "get"},
		},
	)

	if !cfg.Tenant.MultiTenant() {
		// Zero and single tenant clusters need elasticsearch configuration.
		cfg.EnabledControllers = append(cfg.EnabledControllers, "authorization", "elasticsearchconfiguration")
		if cfg.ManagementCluster != nil && cfg.Tenant == nil {
			// Enterprise requires the managedcluster controller to push licenses.
			cfg.EnabledControllers = append(cfg.EnabledControllers, "managedcluster")
		}
	}

	cfg.NetworkPolicy = esKubeControllersCalicoSystemPolicy(cfg)
	cfg.DeprecatedNetworkPolicyName = "es-kube-controller-access"
	cfg.ExtraEnv = esKubeControllersEnv(cfg)

	return kubecontrollers.NewKubeControllers(cfg)
}

// esKubeControllersEnv builds the enterprise env vars for es-calico-kube-controllers.
func esKubeControllersEnv(cfg *kubecontrollers.KubeControllersConfiguration) []corev1.EnvVar {
	var env []corev1.EnvVar

	if cfg.Tenant != nil {
		env = append(env, corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID})
	}

	// What started as a workaround is now the default behaviour. This feature uses our backend in order to
	// log into Kibana for users from external identity providers, rather than configuring an authn realm
	// in the Elastic stack.
	env = append(env, corev1.EnvVar{Name: "ENABLE_ELASTICSEARCH_OIDC_WORKAROUND", Value: "true"})
	if cfg.Authentication != nil {
		env = append(env,
			corev1.EnvVar{Name: "OIDC_AUTH_USERNAME_PREFIX", Value: cfg.Authentication.Spec.UsernamePrefix},
			corev1.EnvVar{Name: "OIDC_AUTH_GROUP_PREFIX", Value: cfg.Authentication.Spec.GroupsPrefix},
		)
	}

	if cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: cfg.TrustedBundle.MountPath()})
	}
	if cfg.Installation.CalicoNetwork != nil && cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	if !cfg.Tenant.MultiTenant() {
		_, esHost, esPort, _ := url.ParseEndpoint(relasticsearch.GatewayEndpoint(rmeta.OSTypeLinux, cfg.ClusterDomain, render.ElasticsearchNamespace))
		env = append(env,
			relasticsearch.ElasticHostEnvVar(esHost),
			relasticsearch.ElasticPortEnvVar(esPort),
			relasticsearch.ElasticUsernameEnvVar(ElasticsearchKubeControllersUserSecret),
			relasticsearch.ElasticPasswordEnvVar(ElasticsearchKubeControllersUserSecret),
			relasticsearch.ElasticCAEnvVar(rmeta.OSTypeLinux),
		)
	}

	return env
}

// kubeControllersEnterpriseCommonRules are the Calico Enterprise cluster role rules
// shared by calico-kube-controllers and es-calico-kube-controllers. wafEnabled adds
// the WAF v3 (Gateway API add-on) rules; managedCluster adds the license-push rule a
// managed cluster's kube-controllers needs.
func kubeControllersEnterpriseCommonRules(wafEnabled, managedCluster bool) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
		},
		{
			// The Federated Services Controller needs access to the remote kubeconfig secret
			// in order to create a remote syncer.
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// Needed to validate the license
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			// Needed to update the status of the LicenseKey with the result of license validation.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"packetcaptures/status"},
			Verbs:     []string{"update"},
		},
	}

	if wafEnabled {
		rules = append(rules, wafRules()...)
	}

	if managedCluster {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "create", "update", "list", "watch"},
			},
		)
	}

	return rules
}

// calicoKubeControllersEnterpriseRules are the enterprise cluster role rules layered
// onto calico-kube-controllers: the shared enterprise rules plus the calico-specific
// ones (federated endpoints, license usage reporting).
func calicoKubeControllersEnterpriseRules(wafEnabled, managedCluster bool) []rbacv1.PolicyRule {
	rules := kubeControllersEnterpriseCommonRules(wafEnabled, managedCluster)
	return append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"remoteclusterconfigurations"},
			Verbs:     []string{"watch", "list", "get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"create", "update", "delete"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"usage.tigera.io"},
			Resources: []string{"licenseusagereports"},
			Verbs:     []string{"create", "update", "delete", "watch", "list", "get"},
		},
	)
}

// calicoKubeControllersEnterpriseControllers are the enterprise controllers added to
// the calico-kube-controllers ENABLED_CONTROLLERS list (on top of the base
// node,loadbalancer). applicationlayer is added only when the WAF extension is on.
func calicoKubeControllersEnterpriseControllers(wafEnabled bool) []string {
	controllers := []string{"service", "federatedservices", "usage"}
	if wafEnabled {
		controllers = append(controllers, "applicationlayer")
	}
	return controllers
}

// wafRules are the WAF v3 (Gateway API add-on) cluster role rules, gated by
// GatewayAPI.spec.extensions.waf.state == Enabled.
func wafRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		// Application-layer (gateway-addons) reconcilers reconcile WAF resources
		// against Gateway API targetRefs and emit events on the policy objects.
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies", "globalwafpolicies",
				"wafplugins", "globalwafplugins",
				"wafvalidationpolicies", "globalwafvalidationpolicies",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies/status", "globalwafpolicies/status",
				"wafplugins/status", "globalwafplugins/status",
				"wafvalidationpolicies/status", "globalwafvalidationpolicies/status",
			},
			Verbs: []string{"get", "update", "patch"},
		},
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies/finalizers", "globalwafpolicies/finalizers",
				"wafplugins/finalizers", "globalwafplugins/finalizers",
				"wafvalidationpolicies/finalizers", "globalwafvalidationpolicies/finalizers",
			},
			Verbs: []string{"update"},
		},
		{
			// Validate Gateway API targetRefs and surface attachment status.
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes", "tcproutes", "tlsroutes", "grpcroutes"},
			Verbs:     []string{"get", "list", "watch", "update", "patch"},
		},
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways/status", "httproutes/status", "tcproutes/status", "tlsroutes/status", "grpcroutes/status"},
			Verbs:     []string{"get", "update", "patch"},
		},
		// controller-runtime Reconcilers (e.g. the applicationlayer manager) record
		// events on watched objects via Recorder.Eventf; both core and events.k8s.io
		// API groups are emitted depending on the kubernetes version.
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
		{
			APIGroups: []string{"events.k8s.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
		// Application-layer reconciler replicates the WAF wasm pull Secret from
		// the controller namespace (calico-system) into each WAFPolicy's
		// namespace so the rendered EnvoyExtensionPolicy can reference it. Also
		// replicates CA-cert ConfigMaps when WASM_CA_CERT is set.
		{
			APIGroups: []string{""},
			Resources: []string{"secrets", "configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Application-layer reconciler emits one EnvoyExtensionPolicy per WAF
		// targetRef to bind the Coraza wasm filter at the gateway / route.
		{
			APIGroups: []string{"gateway.envoyproxy.io"},
			Resources: []string{"envoyextensionpolicies"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Application-layer reconciler stamps each namespace with its allocated WAF
		// rule-id range (applicationlayer.projectcalico.org/waf-id-range annotation)
		// so application operators can author in-range rules. The base role already
		// grants namespaces get/list/watch; the annotation write needs patch/update.
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "patch", "update"},
		},
	}
}

func esKubeControllersCalicoSystemPolicy(cfg *kubecontrollers.KubeControllersConfiguration) *v3.NetworkPolicy {
	if cfg.ManagementClusterConnection != nil {
		return nil
	}

	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(443, 6443, 12388),
			},
		},
	}...)

	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().ESGatewayEntityRule(),
		},
	}...)

	networkpolicyHelper := networkpolicy.Helper(cfg.Tenant.MultiTenant(), cfg.Namespace)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsKubeControllerNetworkPolicyName,
			Namespace: cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(EsKubeController),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

// wafRenderData is the controller-produced WAF v3 (Gateway API add-on) state the
// installation hook hands the kube-controllers modifier through the render context.
// The zero value (enabled false) means the modifier deletes the webhook objects.
type wafRenderData struct {
	enabled    bool
	wasmImage  string
	pullSecret *corev1.Secret
	caCert     *corev1.ConfigMap
	webhookTLS certificatemanagement.KeyPairInterface
	caBundle   []byte
}

// buildWAFData reads the GatewayAPI CR and, when the WAF extension is enabled,
// produces everything the modifier needs that it can't compute itself: the resolved
// wasm image, the webhook serving keypair (also returned as a managed keypair), the
// merged wasm pull secret, the wasm CA bundle ConfigMap, and the operator CA PEM.
func buildWAFData(cc extensions.ControllerContext) (wafRenderData, certificatemanagement.KeyPairInterface, error) {
	gw, _, err := gatewayapi.GetGatewayAPI(cc.Ctx, cc.Client)
	if err != nil && !apierrors.IsNotFound(err) {
		return wafRenderData{}, nil, err
	}
	if gw == nil || !gw.Spec.IsWAFGatewayExtensionEnabled() {
		return wafRenderData{}, nil, nil
	}

	in := cc.Installation
	// The wasm is baked into the gateway envoy-proxy image. Resolve it with the same
	// GetReference the base render uses for every image; the hook has the ImageSet here.
	imageSet, err := imageset.GetImageSet(cc.Ctx, cc.Client, in.Variant)
	if err != nil {
		return wafRenderData{}, nil, err
	}
	wasmImage, err := components.GetReference(components.ComponentGatewayAPIEnvoyProxy, in.Registry, in.ImagePath, in.ImagePrefix, imageSet)
	if err != nil {
		return wafRenderData{}, nil, err
	}

	webhookTLS, err := cc.CertificateManager.GetOrCreateKeyPair(
		cc.Client,
		applicationlayer.WAFWebhookServerTLSSecretName,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(applicationlayer.WAFWebhookServiceName, common.CalicoNamespace, cc.ClusterDomain),
	)
	if err != nil {
		return wafRenderData{}, nil, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(in, cc.Client)
	if err != nil {
		return wafRenderData{}, nil, err
	}
	var pullSecret *corev1.Secret
	if len(pullSecrets) > 0 {
		pullSecret, _ = MergeWAFPullSecret(pullSecrets)
	}

	var caCert *corev1.ConfigMap
	if cc.TrustedBundle != nil {
		caCert = cc.TrustedBundle.ConfigMap(common.CalicoNamespace)
		caCert.Name = WASMCACertName
	}

	return wafRenderData{
		enabled:    true,
		wasmImage:  wasmImage,
		pullSecret: pullSecret,
		caCert:     caCert,
		webhookTLS: webhookTLS,
		caBundle:   cc.CertificateManager.KeyPair().GetCertificatePEM(),
	}, webhookTLS, nil
}

// MergeWAFPullSecret synthesizes the dedicated WAF wasm pull secret
// (tigera-waf-pull-secret) by merging the registry auths of every Installation pull
// secret. The EnvoyExtensionPolicy image source takes a single pullSecretRef, so a
// merged secret is the only way to honor multiple Installation pull secrets for the
// Coraza wasm OCI pull (e.g. the Tigera pull secret plus a private registry mirror).
//
// If the same registry appears in more than one secret, the first secret in
// Installation order wins. Secrets that cannot be parsed are skipped and their names
// returned, so the caller can log them without failing the reconcile. Returns a nil
// Secret when no registry auths could be collected.
func MergeWAFPullSecret(pullSecrets []*corev1.Secret) (*corev1.Secret, []string) {
	merged := map[string]json.RawMessage{}
	var skipped []string
	for _, s := range pullSecrets {
		auths, err := registryAuths(s)
		if err != nil {
			skipped = append(skipped, s.Name)
			continue
		}
		for registry, auth := range auths {
			if _, ok := merged[registry]; !ok {
				merged[registry] = auth
			}
		}
	}
	if len(merged) == 0 {
		return nil, skipped
	}

	// Marshalling a map sorts its keys, so the rendered bytes are deterministic and
	// do not churn the object on every reconcile.
	data, err := json.Marshal(map[string]map[string]json.RawMessage{"auths": merged})
	if err != nil {
		// Each auth entry round-trips from a successful Unmarshal above, so this
		// cannot fail in practice; treat it as nothing to render.
		return nil, skipped
	}

	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WASMPullSecretName, Namespace: common.CalicoNamespace},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: data},
	}, skipped
}

// registryAuths extracts the per-registry auth entries from a pull secret of either
// the dockerconfigjson type (auths nested under an "auths" key) or the legacy
// dockercfg type (a bare registry -> auth map).
func registryAuths(s *corev1.Secret) (map[string]json.RawMessage, error) {
	if raw, ok := s.Data[corev1.DockerConfigJsonKey]; ok {
		var cfg struct {
			Auths map[string]json.RawMessage `json:"auths"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, err
		}
		if len(cfg.Auths) == 0 {
			return nil, fmt.Errorf("secret %s has no auths entries", s.Name)
		}
		return cfg.Auths, nil
	}
	if raw, ok := s.Data[corev1.DockerConfigKey]; ok {
		var auths map[string]json.RawMessage
		if err := json.Unmarshal(raw, &auths); err != nil {
			return nil, err
		}
		if len(auths) == 0 {
			return nil, fmt.Errorf("secret %s has no auths entries", s.Name)
		}
		return auths, nil
	}
	return nil, fmt.Errorf("secret %s has neither a %s nor a %s key", s.Name, corev1.DockerConfigJsonKey, corev1.DockerConfigKey)
}
