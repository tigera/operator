// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package nonclusterhost

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	NonClusterHostObjectName = "tigera-noncluster-host"
)

type Config struct {
	NonClusterHost operatorv1.NonClusterHostSpec
}

func NonClusterHost(cfg *Config) render.Component {
	return &nonClusterHostComponent{
		cfg: cfg,
	}
}

type nonClusterHostComponent struct {
	cfg *Config
}

func (c *nonClusterHostComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (c *nonClusterHostComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (c *nonClusterHostComponent) Objects() ([]client.Object, []client.Object) {
	toCreate := []client.Object{
		c.serviceAccount(),
		c.tokenSecret(),
		c.clusterRole(),
		c.clusterRoleBinding(),
	}
	return toCreate, nil
}

func (c *nonClusterHostComponent) Ready() bool {
	return true
}

func (c *nonClusterHostComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NonClusterHostObjectName,
			Namespace: common.CalicoNamespace,
		},
	}
}

func (c *nonClusterHostComponent) tokenSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NonClusterHostObjectName,
			Namespace: common.CalicoNamespace,
			// The annotation below will result in the auto-creation of spec.data.token.
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": NonClusterHostObjectName,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}
}

func (c *nonClusterHostComponent) clusterRole() *rbacv1.ClusterRole {
	// calico node rules
	rules := []rbacv1.PolicyRule{
		{
			// Calico uses endpoint slices for service-based network policy rules.
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"list", "watch"},
		},
		{
			// Used to discover Typha endpoints and service IPs for advertisement.
			APIGroups: []string{""},
			Resources: []string{"endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// For enforcing network policies.
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"watch", "list"},
		},
		{
			// For enforcing admin network policies.
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{"adminnetworkpolicies", "baselineadminnetworkpolicies"},
			Verbs:     []string{"watch", "list"},
		},
		{
			// Metadata from these are used in conjunction with network policy.
			APIGroups: []string{""},
			Resources: []string{"pods", "namespaces", "serviceaccounts"},
			Verbs:     []string{"watch", "list"},
		},
		{
			// Calico monitors nodes for some networking configuration.
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// For monitoring Calico-specific configuration.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{
				"bfdconfigurations",
				"bgpconfigurations",
				"clusterinformations",
				"egressgatewaypolicies",
				"externalnetworks",
				"felixconfigurations",
				"globalnetworkpolicies",
				"globalnetworksets",
				"hostendpoints",
				"ipamblocks",
				"ippools",
				"licensekeys",
				"networkpolicies",
				"networksets",
				"packetcaptures",
				"remoteclusterconfigurations",
				"stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"stagednetworkpolicies",
				"tiers",
			},
			Verbs: []string{"get", "list", "watch"},
		},
	}

	// calico fluent-bit rules
	rules = append(rules, []rbacv1.PolicyRule{
		{
			// Used for creating service account tokens to be used by the linseed out plugin.
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		},
		{
			// Used to read endpoint field from the NonClusterHost resource.
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"nonclusterhosts"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// Allow post flow logs to linseed.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"flowlogs"},
			Verbs:     []string{"create"},
		},
	}...)

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: NonClusterHostObjectName,
		},
		Rules: rules,
	}
}

func (c *nonClusterHostComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: NonClusterHostObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     NonClusterHostObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      NonClusterHostObjectName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}
