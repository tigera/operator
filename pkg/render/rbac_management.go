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

// RBACManagementEscalationRules returns the permission set the rbacsync
// controller (in calico-kube-controllers) holds so it can write the RBAC
// management UI's managed roles. The rbacsync controller acts as its own
// ServiceAccount, and Kubernetes rejects a write to a Role or ClusterRole as
// privilege escalation unless the writer already holds every permission that
// role grants. This set is therefore a superset of the rules in those managed
// roles; the managed roles themselves are defined in calico/kube-controllers.
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
		// The managed Webhooks role grants creating the webhook backing Secret and
		// patching webhooks-secret, so the writer must hold the same to pass the
		// escalation check. create cannot be name-scoped (the name is in the
		// request body, not the URL path), so it is cluster-wide here.
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{"webhooks-secret"},
			Verbs:         []string{"patch"},
		},
		// LMA log roles' scope verb (per-cluster log access roles).
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"cluster"},
			Verbs:     []string{"get"},
		},
	}
}
