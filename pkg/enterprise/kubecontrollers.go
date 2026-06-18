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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/url"
)

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
