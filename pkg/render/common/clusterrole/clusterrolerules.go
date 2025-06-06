// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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

package clusterrole

import (
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
)

// CalicoKubeControllersClusterRoleRules defines RBAC rules for calico-kube-controller pods
// and for guardian to handle kube-controller requests from the management cluster.
func CalicoKubeControllersClusterRoleRules(isEnterpriseCluster bool, isOpenShift bool, isManagedCluster bool) []rbacv1.PolicyRule {
	rules := KubeControllersRoleCommonRules(isOpenShift)
	if isEnterpriseCluster {
		rules = append(rules, KubeControllersRoleEnterpriseCommonRules(isManagedCluster)...)
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"crd.projectcalico.org"},
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
	return rules
}

func KubeControllersRoleCommonRules(isOpenShift bool) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			// Nodes are watched to monitor for deletions.
			APIGroups: []string{""},
			Resources: []string{"nodes", "endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// Pods are watched to check for existence as part of IPAM GC.
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services", "services/status"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			// IPAM resources are manipulated in response to node and block updates, as well as periodic triggers.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"ipreservations"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles", "networksets", "ipamconfigs"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		{
			// Pools are watched to maintain a mapping of blocks to IP pools.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"ippools"},
			Verbs:     []string{"list", "watch"},
		},
		{
			// Needs access to update clusterinformations.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "create", "update", "list", "watch"},
		},
		{
			// Needs to manage hostendpoints.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		{
			// Needs to manipulate kubecontrollersconfiguration, which contains
			// its config.  It creates a default if none exists, and updates status
			// as well.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"kubecontrollersconfigurations"},
			Verbs:     []string{"get", "create", "list", "update", "watch"},
		},
		{
			// calico-kube-controllers requires tiers create
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create"},
		},
	}

	if isOpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return rules
}

func KubeControllersRoleEnterpriseCommonRules(isManagedCluster bool) []rbacv1.PolicyRule {
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
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			// Needed to validate the license
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "update"},
		},
	}

	if isManagedCluster {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "create", "update", "list", "watch"},
			},
			// Grant permissions to access ClusterInformation resources in managed clusters.
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "list", "watch"},
			},
		)
	}

	return rules
}
