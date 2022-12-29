// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package runtimesecurity

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This file contains coding that we only need in order to remove legacy components from an existing
// management cluster.

const ResourceNameSashaJob = "tigera-ee-sasha"

func (c *component) sashaCronJob() *batchv1.CronJob {
	return &batchv1.CronJob{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameSashaJob,
			Namespace: NameSpaceRuntimeSecurity,
		},
	}
}

func (c *component) oldSashaServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameSashaJob, Namespace: NameSpaceRuntimeSecurity},
	}
}
