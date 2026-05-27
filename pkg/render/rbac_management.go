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

package render

import rbacv1 "k8s.io/api/rbac/v1"

// RBACManagementEscalationRules returns the escalation-prevention rules shared
// by the calico-manager and calico-kube-controllers roles when the RBAC
// management UI feature is enabled. Every permission the feature grants to a
// managed role must also be held by the SA performing the binding, otherwise
// the K8s RBAC engine rejects the write as a privilege escalation. The two
// consumers add their own non-shared rules on top — keep this list aligned
// with the set of roles the RBAC management UI maintains.
func RBACManagementEscalationRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		// Full CRUD on the RBAC objects the feature writes.
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings", "rolebindings"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Tier/policy resources covered by generated tier roles.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"tier.networkpolicies",
				"tier.stagednetworkpolicies",
				"tier.globalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"networkpolicies",
				"globalnetworkpolicies",
				"stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Resource-role payload set (the feature-level ClusterRoles maintained
		// by rbacsync).
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"uisettings",
				"uisettingsgroups",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"deeppacketinspections",
				"deeppacketinspections/status",
				"egressgatewaypolicies",
				"externalnetworks",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"alertexceptions",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"globalreports",
				"globalreports/status",
				"globalreporttypes",
				"packetcaptures",
				"packetcaptures/files",
				"securityeventwebhooks",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// LMA log roles' scope verb (per-cluster log access roles).
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"cluster"},
			Verbs:     []string{"get"},
		},
		// Read on the customer-owned IdP directory ConfigMap (drives the RBAC
		// management UI's directory cache and the cascading cleanup of managed
		// bindings when a group is removed).
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"tigera-idp-groups"},
			Verbs:         []string{"get", "list", "watch"},
		},
	}
}
