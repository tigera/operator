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

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/common"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ManagementCluster is the management-cluster setup the renderers need. A nil value
// means the cluster does not manage others.
type ManagementCluster struct {
	// Address is the tunnel endpoint managed clusters dial.
	Address string

	// TunnelSecretName is the tunnel CA secret, already defaulted.
	TunnelSecretName string
}

// NewManagementCluster defaults the tunnel CA secret when the caller has no override.
func NewManagementCluster(address, tunnelSecretName string) *ManagementCluster {
	if tunnelSecretName == "" {
		tunnelSecretName = VoltronTunnelSecretName
	}
	return &ManagementCluster{Address: address, TunnelSecretName: tunnelSecretName}
}

// TunnelSecretRBAC returns RBAC objects granting get access to the tunnel CA secret.
// For multi-tenant management clusters, this returns a ClusterRole/ClusterRoleBinding so the
// service account can read per-tenant secrets across namespaces. For single-tenant clusters,
// this returns a namespace-scoped Role/RoleBinding in calico-system.
func TunnelSecretRBAC(rbacName string, serviceAccountName string, mc *ManagementCluster, multiTenant bool) []client.Object {
	secretName := VoltronTunnelSecretName
	if mc != nil {
		secretName = mc.TunnelSecretName
	}
	rules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{secretName},
		},
	}

	if multiTenant {
		return []client.Object{
			&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name: rbacName,
				},
				Rules: rules,
			},
			&rbacv1.ClusterRoleBinding{
				TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name: rbacName,
				},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     rbacName,
					APIGroup: "rbac.authorization.k8s.io",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      serviceAccountName,
						Namespace: common.CalicoNamespace,
					},
				},
			},
		}
	}

	return []client.Object{
		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbacName,
				Namespace: common.CalicoNamespace,
			},
			Rules: rules,
		},
		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbacName,
				Namespace: common.CalicoNamespace,
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     rbacName,
				APIGroup: "rbac.authorization.k8s.io",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName,
					Namespace: common.CalicoNamespace,
				},
			},
		},
	}
}
