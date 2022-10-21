// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	podWatcherRequestCPU    = "250m"
	podWatcherRequestMemory = "100Mi"
	podWatcherLimitCPU      = "1"
	podWatcherLimitMemory   = "600Mi"
)

func (c *component) podWatcherServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssurancePodWatcher, Namespace: NameSpaceImageAssurance},
	}
}

func (c *component) podWatcherAPIAccessTokenSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PodWatcherAPIAccessSecretName,
			Namespace: NameSpaceImageAssurance,
		},
		Data: map[string][]byte{
			"token": c.config.PodWatcherAPIAccessToken,
		},
	}
}

func (c *component) podWatcherRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssurancePodWatcher,
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

func (c *component) podWatcherClusterRoles() []*rbacv1.ClusterRole {
	return []*rbacv1.ClusterRole{
		{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      PodWatcherClusterRoleName,
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
						"registries",
					},
					Verbs: []string{
						"list", "get",
					},
				},
				{
					APIGroups: []string{
						"imageassurance.tigera.io",
					},
					Resources: []string{
						"repositories",
					},
					Verbs: []string{
						"get",
					},
				},
				{
					APIGroups: []string{
						"imageassurance.tigera.io",
					},
					Resources: []string{
						"images",
					},
					Verbs: []string{
						"get", "create",
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
						"create",
					},
				},
				{
					APIGroups: []string{
						"imageassurance.tigera.io",
					},
					Resources: []string{
						"events",
					},
					Verbs: []string{
						"create",
					},
				},
			},
		},
		{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ResourceNameImageAssurancePodWatcher,
				Namespace: NameSpaceImageAssurance,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		},
	}
}

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
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssurancePodWatcher,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) podWatcherClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssurancePodWatcher,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     ResourceNameImageAssurancePodWatcher,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssurancePodWatcher,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) podWatcherDeployment() *appsv1.Deployment {
	annots := c.config.TrustedCertBundle.HashAnnotations()
	annots[rcimageassurance.ImageAssuranceCertHashAnnotation] = rmeta.AnnotationHash(c.config.tlsHash)
	annots[rcimageassurance.ImageAssuranceAPITokenHashAnnontation] = rmeta.AnnotationHash(c.config.PodWatcherAPIAccessToken)

	env := []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_API_CA", Value: rcimageassurance.CABundlePath},
		{Name: "IMAGE_ASSURANCE_API_SERVICE_URL", Value: rcimageassurance.APIEndpoint},
		{Name: "IMAGE_ASSURANCE_API_TOKEN", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: PodWatcherAPIAccessSecretName},
				Key:                  "token",
			},
		}},
		{Name: "IMAGE_ASSURANCE_MULTI_CLUSTER_FORWARDING_CA", Value: c.config.TrustedCertBundle.MountPath()},
	}

	terminationGracePeriod := int64(30)

	container := corev1.Container{
		Name:            ResourceNameImageAssurancePodWatcher,
		Image:           c.config.podWatcherImage,
		ImagePullPolicy: corev1.PullAlways,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(podWatcherRequestCPU),
				corev1.ResourceMemory: resource.MustParse(podWatcherRequestMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(podWatcherLimitCPU),
				corev1.ResourceMemory: resource.MustParse(podWatcherLimitMemory),
			},
		},
		Env: env,
		VolumeMounts: []corev1.VolumeMount{
			c.config.TrustedCertBundle.VolumeMount(),
			{Name: rcimageassurance.ImageAssuranceSecretName, MountPath: rcimageassurance.CAMountPath, ReadOnly: true},
		},
	}

	podSpec := corev1.PodSpec{
		DNSPolicy:                     corev1.DNSClusterFirst,
		ImagePullSecrets:              c.config.Installation.ImagePullSecrets,
		NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
		RestartPolicy:                 corev1.RestartPolicyAlways,
		ServiceAccountName:            ResourceNameImageAssurancePodWatcher,
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		Containers:                    []corev1.Container{container},
		Volumes:                       c.podWatcherVolumes(),
	}

	replicas := int32(1)
	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssurancePodWatcher,
			Namespace: NameSpaceImageAssurance,
			Labels: map[string]string{
				"k8s-app": ResourceNameImageAssurancePodWatcher,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": ResourceNameImageAssurancePodWatcher,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ResourceNameImageAssurancePodWatcher,
					Namespace: NameSpaceImageAssurance,
					Labels: map[string]string{
						"k8s-app": ResourceNameImageAssurancePodWatcher,
					},
					Annotations: annots,
				},
				Spec: podSpec,
			},
		},
	}

	return &d
}

func (c *component) podWatcherVolumes() []corev1.Volume {
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
