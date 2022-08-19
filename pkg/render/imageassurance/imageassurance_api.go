// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (c *component) apiServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssuranceAPI, Namespace: NameSpaceImageAssurance},
	}
}

func (c *component) apiRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

func (c *component) apiClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
		},
		Rules: []rbacv1.PolicyRule{
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
		},
	}
}

func (c *component) apiClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     ResourceNameImageAssuranceAPI,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssuranceAPI,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) apiRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     ResourceNameImageAssuranceAPI,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssuranceAPI,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) apiService(appName string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": appName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:     "image-assurance-api-port",
					Protocol: corev1.ProtocolTCP,
					Port:     9443,
					TargetPort: intstr.IntOrString{
						IntVal: 5557,
					},
				},
			},
		},
	}
}

func (c *component) apiDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
		},
	}
}
