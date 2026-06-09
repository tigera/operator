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
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
)

func registerGuardian() {
	extensions.Register(operatorv1.CalicoEnterprise, render.GuardianName, extensions.Extension{
		Modify: modifyGuardian,
	})
}

// modifyGuardian layers Calico Enterprise behavior onto the rendered guardian
// objects: the secrets Role/RoleBinding and default UI settings, the
// elasticsearch/kibana service ports, the management-cluster-request cluster
// role rules (which replace the OSS rules), and the CA bundle env vars.
func modifyGuardian(ctx extensions.RenderContext, objs []client.Object) []client.Object {
	gc, _ := ctx.Component.(render.GuardianExtensionContext)

	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.GuardianClusterRoleName); ok {
		role.Rules = guardianEnterpriseRules(gc)
	}

	if svc, ok := extensions.FindObject[*corev1.Service](objs, render.GuardianServiceName); ok {
		svc.Spec.Ports = append(svc.Spec.Ports, guardianEnterpriseServicePorts()...)
	}

	if dep, ok := extensions.FindObject[*appsv1.Deployment](objs, render.GuardianDeploymentName); ok {
		addGuardianEnterpriseEnv(gc, dep)
	}

	return append(objs,
		guardianSecretsRole(),
		guardianSecretRoleBinding(),
		// Default UI settings for this managed cluster.
		render.ManagerClusterWideSettingsGroup(),
		render.ManagerUserSpecificSettingsGroup(),
		render.ManagerClusterWideTigeraLayer(),
		render.ManagerClusterWideDefaultView(),
	)
}

// guardianEnterpriseRules are the cluster role rules guardian needs in Calico
// Enterprise. They wholly replace the OSS rules: the management cluster drives
// guardian over the tunnel, so it needs the union of the rules its components
// require, plus any configured impersonation and the OpenShift SCC.
func guardianEnterpriseRules(gc render.GuardianExtensionContext) []rbacv1.PolicyRule {
	var rules []rbacv1.PolicyRule

	if imp := gc.Impersonation; imp != nil {
		if imp.Users != nil {
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups:     []string{""},
				Resources:     []string{"users"},
				ResourceNames: imp.Users,
				Verbs:         []string{"impersonate"},
			})
		}
		if imp.Groups != nil {
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups:     []string{""},
				Resources:     []string{"groups"},
				ResourceNames: imp.Groups,
				Verbs:         []string{"impersonate"},
			})
		}
		if imp.ServiceAccounts != nil {
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				ResourceNames: imp.ServiceAccounts,
				Verbs:         []string{"impersonate"},
			})
		}
	}

	rules = append(rules, rulesForManagementClusterRequests(gc.OpenShift)...)

	if gc.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return rules
}

func guardianEnterpriseServicePorts() []corev1.ServicePort {
	return []corev1.ServicePort{
		{
			Name:       "elasticsearch",
			Port:       9200,
			TargetPort: intstr.IntOrString{Type: intstr.Int, IntVal: 8080},
			Protocol:   corev1.ProtocolTCP,
		},
		{
			Name:       "kibana",
			Port:       5601,
			TargetPort: intstr.IntOrString{Type: intstr.Int, IntVal: 8080},
			Protocol:   corev1.ProtocolTCP,
		},
	}
}

func addGuardianEnterpriseEnv(gc render.GuardianExtensionContext, dep *appsv1.Deployment) {
	for i := range dep.Spec.Template.Spec.Containers {
		c := &dep.Spec.Template.Spec.Containers[i]
		if c.Name != render.GuardianContainerName {
			continue
		}
		c.Env = append(c.Env,
			corev1.EnvVar{Name: "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: gc.TrustedBundleMountPath},
			corev1.EnvVar{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: gc.TrustedBundleMountPath},
			corev1.EnvVar{Name: "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH", Value: gc.TrustedBundleMountPath},
		)
	}
}

// guardianSecretsRole creates a Role that allows the management cluster to
// provision secrets to the tigera-operator Namespace, used to push secrets the
// managed cluster needs to access / authenticate with the management cluster.
func guardianSecretsRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.GuardianSecretsRole,
			Namespace: common.OperatorNamespace(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"create", "delete", "deletecollection", "update"},
			},
		},
	}
}

func guardianSecretRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.GuardianSecretsRoleBindingName,
			Namespace: common.OperatorNamespace(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     render.GuardianSecretsRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.GuardianServiceAccountName,
				Namespace: render.GuardianNamespace,
			},
		},
	}
}

// rulesForManagementClusterRequests returns the set of RBAC rules guardian needs
// to satisfy requests from the management cluster over the tunnel.
func rulesForManagementClusterRequests(isOpenShift bool) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		// Common rules required to handle requests from multiple components in the management cluster.
		{
			// ID uses read-only permissions and kube-controllers uses both read and write verbs.
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},
		{
			// Allows Linseed to watch namespaces before copying its token.
			// Also enables PolicyRecommendation to watch namespaces,
			// and Manager/kube-controllers to list them.
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// kube-controllers watches Nodes to monitor for deletions.
			// Manager performs a list operation on Nodes.
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// kube-controllers watches Pods to verify existence for IPAM garbage collection.
			// Manager performs get operations on Pods.
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// The Federated Services Controller needs access to the remote kubeconfig secret
			// in order to create a remote syncer.
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// Manager uses list; kube-controllers uses 'get', 'list', 'watch', 'update'.
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			// Needed by kube-controllers to validate licenses; also used by ID.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch"},
		},
		{
			// Manager uses list; PolicyRecommendation & ID uses all verbs.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalnetworksets",
				"networkpolicies",
				"tier.networkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		{
			// Manager uses list; PolicyRecommendation uses all verbs.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		// Rules needed by guardian to handle manager authorization reviews.
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"},
			Verbs:     []string{"list", "get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettings", "uisettingsgroups"},
			Verbs:     []string{"list", "get"},
		},

		// Rules needed by guardian to handle other manager requests.
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		{
			// Allow query server talk to Prometheus via the manager user.
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"calico-node-prometheus:9090",
				"https:calico-api:8080",
			},
			Verbs: []string{"create", "get"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"daemonsets", "replicasets", "statefulsets"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"alertexceptions"},
			Verbs:     []string{"get", "list", "update"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"felixconfigurations"},
			ResourceNames: []string{"default"},
			Verbs:         []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalnetworkpolicies",
				"networksets",
				"stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"tier.globalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
			},
			Verbs: []string{"list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"list"},
		},

		// Rules needed by guardian to handle policy recommendation requests.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},

		// Rules needed by guardian to handle calico-kube-controller requests.
		{
			// Nodes are watched to monitor for deletions.
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services/status"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			// Needs to manage hostendpoints.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},
		{
			// Needs access to update clusterinformations.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"create", "get", "list", "update", "watch"},
		},
		{
			// Needs to manipulate kubecontrollersconfiguration, which contains its config.
			// It creates a default if none exists, and updates status as well.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"kubecontrollersconfigurations"},
			Verbs:     []string{"create", "get", "list", "update", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org", "projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "list", "watch"},
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
			Resources: []string{"remoteclusterconfigurations"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"create", "get", "list", "update", "watch"},
		},
		{
			// Grant permissions to access ClusterInformation resources in managed clusters.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"usage.tigera.io"},
			Resources: []string{"licenseusagereports"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},

		// Rules needed by guardian to handle Intrusion detection requests.
		{
			APIGroups: []string{""},
			Resources: []string{"podtemplates"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"alertexceptions"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		// Rules needed to fetch the compliance reports
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes", "globalreports"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}

	// Rules needed by policy recommendation in openshift.
	if isOpenShift {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.HostNetworkV2},
			},
		)
	}

	return rules
}
