// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package runtimesecurity

import (
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/secret"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This file contains coding that we only need in order to remove legacy components from an existing
// management cluster.

const ResourceNameSashaJob = "tigera-ee-sasha"

func (c *component) sashaCronJob() *batchv1.CronJob {
	const schedule = "*/5 * * * *"

	envVars := []corev1.EnvVar{
		{Name: "PULL_MAX_LAST_MINUTES", Value: "20"},
		{Name: "CLUSTER_NAME", Value: c.esClusterName()},
		// Sasha Phase 0: hashes are embedded as JSON in sasha image used in cron job
		{Name: "HASHES_SOURCE", Value: "local"},
	}

	return &batchv1.CronJob{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameSashaJob,
			Namespace: NameSpaceRuntimeSecurity,
		},
		Spec: batchv1.CronJobSpec{
			Schedule: schedule,
			JobTemplate: batchv1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: ResourceNameSashaJob,
					Labels: map[string]string{
						"k8s-app": ResourceNameSashaJob,
					},
				},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"k8s-app": ResourceNameSashaJob,
							},
						},
						Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
							NodeSelector: c.config.Installation.ControlPlaneNodeSelector,
							Tolerations:  c.config.Installation.ControlPlaneTolerations,
							Containers: []corev1.Container{
								relasticsearch.ContainerDecorate(corev1.Container{
									Name:    ResourceNameSashaJob,
									Image:   c.config.sashaImage,
									Command: []string{"python3", "-m", "sasha.main"},
									Env:     envVars,
									Resources: corev1.ResourceRequirements{
										Limits: corev1.ResourceList{
											corev1.ResourceCPU:    resource.MustParse(ResourceSashaDefaultCPULimit),
											corev1.ResourceMemory: resource.MustParse(ResourceSashaDefaultMemoryLimit),
										},
										Requests: corev1.ResourceList{
											corev1.ResourceCPU:    resource.MustParse(ResourceSashaDefaultCPURequest),
											corev1.ResourceMemory: resource.MustParse(ResourceSashaDefaultMemoryRequest),
										},
									},
								},
									c.config.ESClusterConfig.ClusterName(),
									ElasticsearchSashaJobUserSecretName,
									c.config.ClusterDomain,
									c.SupportedOSType(),
								),
							},
							ImagePullSecrets:   secret.GetReferenceList(c.config.PullSecrets),
							RestartPolicy:      corev1.RestartPolicyNever,
							ServiceAccountName: ResourceNameSashaJob,
						}),
					},
				},
			},
		},
	}
}

func (c *component) oldSashaServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameSashaJob, Namespace: NameSpaceRuntimeSecurity},
	}
}
