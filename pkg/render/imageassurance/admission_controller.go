package imageassurance

import (
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	AdmissionControllerAPIClusterRoleName = "tigera-image-assurance-admission-controller-api"
)

func (c *component) admissionControllerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: AdmissionControllerAPIClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{
				"imageassurance.tigera.io",
			},
			Resources: []string{
				"organizations",
			},
			Verbs: []string{
				"get",
			},
			ResourceNames: []string{
				c.config.ConfigurationConfigMap.Data[rcimageassurance.ConfigurationConfigMapOrgIDKey],
			},
		},
			{
				APIGroups: []string{
					"imageassurance.tigera.io",
				},
				Resources: []string{
					"registries", "repositories", "images",
				},
				Verbs: []string{
					"get", "list",
				},
			},
		},
	}
}
