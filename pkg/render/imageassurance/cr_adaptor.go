// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

package imageassurance

import (
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CRAdaptorAPIClusterRoleName = "tigera-image-assurance-cr-adaptor-api-access"
)

func (c *component) crAdaptorClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: CRAdaptorAPIClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"imageassurance.tigera.io"},
				Resources: []string{"organizations"},
				Verbs:     []string{"get"},
				ResourceNames: []string{
					c.config.ConfigurationConfigMap.Data[rcimageassurance.ConfigurationConfigMapOrgIDKey],
				},
			},
			{
				APIGroups: []string{"imageassurance.tigera.io"},
				Resources: []string{"pods"},
				Verbs:     []string{"create", "update", "delete", "get"},
			},
			{
				APIGroups: []string{"imageassurance.tigera.io"},
				Resources: []string{"registries"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"imageassurance.tigera.io"},
				Resources: []string{"repositories"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"imageassurance.tigera.io"},
				Resources: []string{"images"},
				Verbs:     []string{"create"},
			},
		},
	}
}
