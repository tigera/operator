// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// migratorServiceAccount is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) migratorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssuranceDBMigrator, Namespace: NameSpaceImageAssurance},
	}
}

// migratorRole is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) migratorRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceDBMigrator,
			Namespace: NameSpaceImageAssurance,
		},
	}
}

// migratorRoleBinding is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) migratorRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceDBMigrator,
			Namespace: NameSpaceImageAssurance,
		},
	}
}

// migratorJob is used ONLY to delete a resource that's no longer in use from clusters that installed it.
func (c *component) migratorJob() *batchv1.Job {
	j := batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceDBMigrator,
			Namespace: NameSpaceImageAssurance,
		},
	}

	return &j
}
