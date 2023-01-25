// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package imageassurance

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// podWatcherServiceAccount is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) podWatcherServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssurancePodWatcher, Namespace: NameSpaceImageAssurance},
	}
}

// podWatcherAPIAccessTokenSecret is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) podWatcherAPIAccessTokenSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PodWatcherAPIAccessSecretName,
			Namespace: NameSpaceImageAssurance,
		},
	}
}

// podWatcherRole is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) podWatcherRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssurancePodWatcher,
			Namespace: NameSpaceImageAssurance,
		},
	}
}

// podWatcherClusterRoles is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) podWatcherClusterRoles() []*rbacv1.ClusterRole {
	return []*rbacv1.ClusterRole{
		{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      PodWatcherClusterRoleName,
				Namespace: NameSpaceImageAssurance,
			},
		},
		{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ResourceNameImageAssurancePodWatcher,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

// podWatcherRoleBinding is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) podWatcherRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssurancePodWatcher,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     ResourceNameImageAssurancePodWatcher,
		},
	}
}

// podWatcherClusterRoleBinding is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) podWatcherClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssurancePodWatcher,
			Namespace: NameSpaceImageAssurance,
		},
	}
}

// podWatcherDeployment is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) podWatcherDeployment() *appsv1.Deployment {
	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssurancePodWatcher,
			Namespace: NameSpaceImageAssurance,
		},
	}

	return &d
}
