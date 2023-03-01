// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package imageassurance

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
)

const (
	OperatorAPIClusterRoleName = "tigera-image-assurance-operator-api-access"
)

func (c *component) operatorClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: OperatorAPIClusterRoleName,
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
		},
	}
}
