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
	scannerRequestCPU    = "250m"
	scannerRequestMemory = "4Gi"
	scannerLimitCPU      = "1"
	scannerLimitMemory   = "4Gi"
)

func (c *component) scannerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssuranceScanner, Namespace: NameSpaceImageAssurance},
	}
}

func (c *component) scannerAPIAccessTokenSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ScannerAPIAccessSecretName,
			Namespace: NameSpaceImageAssurance,
		},
		Data: map[string][]byte{
			"token": c.config.ScannerAPIAccessToken,
		},
	}
}

func (c *component) scannerRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceScanner,
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

func (c *component) scannerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ScannerClusterRoleName,
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
					"get", "update",
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
					"get", "update",
				},
			},
			{
				APIGroups: []string{
					"imageassurance.tigera.io",
				},
				Resources: []string{
					"events", "vulnerabilities",
				},
				Verbs: []string{
					"create",
				},
			},
		},
	}
}

func (c *component) scannerRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceScanner,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     ResourceNameImageAssuranceScanner,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssuranceScanner,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) scannerCLIClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ScannerCLIClusterRoleName,
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
					"registries", "repositories", "images",
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
					"create",
				},
			},
			{
				APIGroups: []string{
					"imageassurance.tigera.io",
				},
				Resources: []string{
					"vulnerabilities",
				},
				Verbs: []string{
					"create",
				},
			},
		},
	}
}

func (c *component) scannerDeployment() *appsv1.Deployment {

	annots := map[string]string{
		rcimageassurance.ImageAssuranceCertHashAnnotation: rmeta.AnnotationHash(c.config.tlsHash),
	}

	env := []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_SCANNER_RETRIES", Value: "3"},
		{Name: "IMAGE_ASSURANCE_TENANT_ENCRYPTION_KEY", Value: "/tenant-key/encryption_key"},
		{Name: "IMAGE_ASSURANCE_CA_BUNDLE_PATH", Value: rcimageassurance.CABundlePath},
		{Name: "IMAGE_ASSURANCE_API_SERVICE_URL", Value: rcimageassurance.APIEndpoint},
		{Name: "IMAGE_ASSURANCE_API_TOKEN", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: ScannerAPIAccessSecretName},
				Key:                  "token",
			},
		}},
	}

	terminationGracePeriod := int64(30)

	container := corev1.Container{
		Name:            ResourceNameImageAssuranceScanner,
		Image:           c.config.scannerImage,
		ImagePullPolicy: corev1.PullAlways,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(scannerRequestCPU),
				corev1.ResourceMemory: resource.MustParse(scannerRequestMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(scannerLimitCPU),
				corev1.ResourceMemory: resource.MustParse(scannerLimitMemory),
			},
		},
		Env: env,
		VolumeMounts: []corev1.VolumeMount{
			{Name: rcimageassurance.ImageAssuranceSecretName, MountPath: rcimageassurance.CAMountPath, ReadOnly: true},
		},
	}

	podSpec := corev1.PodSpec{
		DNSPolicy:                     corev1.DNSClusterFirst,
		ImagePullSecrets:              c.config.Installation.ImagePullSecrets,
		NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
		RestartPolicy:                 corev1.RestartPolicyAlways,
		ServiceAccountName:            ResourceNameImageAssuranceScanner,
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		Containers:                    []corev1.Container{container},
		Volumes:                       c.scannerVolumes(),
	}

	replicas := int32(1)
	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceScanner,
			Namespace: NameSpaceImageAssurance,
			Labels: map[string]string{
				"k8s-app": ResourceNameImageAssuranceScanner,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": ResourceNameImageAssuranceScanner,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ResourceNameImageAssuranceScanner,
					Namespace: NameSpaceImageAssurance,
					Labels: map[string]string{
						"k8s-app": ResourceNameImageAssuranceScanner,
					},
					Annotations: annots,
				},
				Spec: podSpec,
			},
		},
	}

	return &d
}

func (c *component) scannerVolumes() []corev1.Volume {
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
	}
}
