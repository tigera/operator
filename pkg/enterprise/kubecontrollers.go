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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/url"
)

// registerKubeControllers registers the calico-kube-controllers modifier. There is
// no image override: kube-controllers runs from the combined calico image, which
// resolves by variant in the base render.
func registerKubeControllers(v *extensions.Variant) {
	v.Modify(render.ComponentNameKubeControllers, modifyKubeControllers)
}

// modifyKubeControllers layers the Calico Enterprise metrics serving TLS onto the
// rendered calico-kube-controllers deployment: the env pointing at the keypair, the
// volume + mount, the cert-management init container (when in use), and the pod hash
// annotation that rolls the pod on cert rotation. The keypair has cluster side
// effects, so the installation extension creates it and hands it in via rc. In core
// (calico) it is never created, so the base deployment carries no metrics TLS.
func modifyKubeControllers(rc extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
	tls := installationData(rc).kubeControllerTLS
	if tls == nil {
		return objs, del
	}

	dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController)
	if !ok {
		return objs, del
	}
	spec := &dp.Spec.Template.Spec
	spec.Volumes = append(spec.Volumes, tls.Volume())

	for i := range spec.Containers {
		c := &spec.Containers[i]
		if c.Name != kubecontrollers.KubeController {
			continue
		}
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

	if dp.Spec.Template.Annotations == nil {
		dp.Spec.Template.Annotations = map[string]string{}
	}
	dp.Spec.Template.Annotations[tls.HashAnnotationKey()] = tls.HashAnnotationValue()

	return objs, del
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
	cfg.Rules = append(cfg.Rules, kubecontrollers.KubeControllersRoleEnterpriseCommonRules(cfg)...)
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
