// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package imageassurance

import (
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	runtimeCleanerRequestCPU    = "250m"
	runtimeCleanerRequestMemory = "50Mi"
	runtimeCleanerLimitCPU      = "500m"
	runtimeCleanerLimitMemory   = "100Mi"
)

func (c *component) runtimeCleanerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssuranceRuntimeCleaner, Namespace: NameSpaceImageAssurance},
	}
}

func (c *component) runtimeCleanerAPIAccessTokenSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RuntimeCleanerAPIAccessSecretName,
			Namespace: NameSpaceImageAssurance,
		},
		Data: map[string][]byte{
			"token": c.config.RuntimeCleanerAPIAccessToken,
		},
	}
}

func (c *component) runtimeCleanerRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceRuntimeCleaner,
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

func (c *component) runtimeCleanerClusterRoles() []*rbacv1.ClusterRole {
	return []*rbacv1.ClusterRole{
		{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      RuntimeCleanerAPIAccessResourceName,
				Namespace: NameSpaceImageAssurance,
			},
			Rules: []rbacv1.PolicyRule{
				{
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
						"pods",
					},
					Verbs: []string{
						"get", "list", "delete",
					},
				},
			},
		},
		{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ResourceNameImageAssuranceRuntimeCleaner,
				Namespace: NameSpaceImageAssurance,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs:     []string{"get", "list"},
				},
			},
		},
	}
}

func (c *component) runtimeCleanerRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceRuntimeCleaner,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     ResourceNameImageAssuranceRuntimeCleaner,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssuranceRuntimeCleaner,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) runtimeCleanerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceRuntimeCleaner,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     ResourceNameImageAssuranceRuntimeCleaner,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssuranceRuntimeCleaner,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) runtimeCleanerDeployment() *appsv1.Deployment {
	annots := c.config.TrustedCertBundle.HashAnnotations()
	annots[rcimageassurance.ImageAssuranceCertHashAnnotation] = rmeta.AnnotationHash(c.config.tlsHash)
	annots[rcimageassurance.ImageAssuranceRuntimeCleanerAPITokenHashAnnontation] = rmeta.AnnotationHash(c.config.RuntimeCleanerAPIAccessToken)

	env := []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_API_CA", Value: rcimageassurance.CABundlePath},
		{Name: "IMAGE_ASSURANCE_API_SERVICE_URL", Value: rcimageassurance.APIEndpoint},
		{Name: "IMAGE_ASSURANCE_API_TOKEN", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: RuntimeCleanerAPIAccessSecretName},
				Key:                  "token",
			},
		}},
		{Name: "IMAGE_ASSURANCE_MULTI_CLUSTER_FORWARDING_CA", Value: c.config.TrustedCertBundle.MountPath()},
		{Name: "IMAGE_ASSURANCE_POLLING_INTERVAL_IN_SECONDS", Value: "300"},
	}

	terminationGracePeriod := int64(30)

	container := corev1.Container{
		Name:            ResourceNameImageAssuranceRuntimeCleaner,
		Image:           c.config.runtimeCleanerImage,
		ImagePullPolicy: corev1.PullAlways,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(runtimeCleanerRequestCPU),
				corev1.ResourceMemory: resource.MustParse(runtimeCleanerRequestMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(runtimeCleanerLimitCPU),
				corev1.ResourceMemory: resource.MustParse(runtimeCleanerLimitMemory),
			},
		},
		Env: env,
		VolumeMounts: []corev1.VolumeMount{
			c.config.TrustedCertBundle.VolumeMount(rmeta.OSTypeLinux),
			{Name: rcimageassurance.ImageAssuranceSecretName, MountPath: rcimageassurance.CAMountPath, ReadOnly: true},
		},
	}

	podSpec := corev1.PodSpec{
		DNSPolicy:                     corev1.DNSClusterFirst,
		ImagePullSecrets:              c.config.Installation.ImagePullSecrets,
		RestartPolicy:                 corev1.RestartPolicyAlways,
		ServiceAccountName:            ResourceNameImageAssuranceRuntimeCleaner,
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		Containers:                    []corev1.Container{container},
		Volumes:                       c.runtimeCleanerVolumes(),
	}

	replicas := int32(1)
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceRuntimeCleaner,
			Namespace: NameSpaceImageAssurance,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        ResourceNameImageAssuranceRuntimeCleaner,
					Namespace:   NameSpaceImageAssurance,
					Annotations: annots,
				},
				Spec: podSpec,
			},
		},
	}
}

func (c *component) runtimeCleanerVolumes() []corev1.Volume {
	return []corev1.Volume{
		{
			Name: rcimageassurance.ImageAssuranceSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					Items: []corev1.KeyToPath{{
						Key:  "tls.crt",
						Path: "tls.crt",
					}},
					SecretName: APICertSecretName,
				},
			},
		},
		c.config.TrustedCertBundle.Volume(),
	}
}
