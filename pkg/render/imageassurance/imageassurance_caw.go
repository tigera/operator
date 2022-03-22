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
	cawRequestCPU    = "0.25"
	cawRequestMemory = "50Mi"
	cawLimitCPU      = "0.75"
	cawLimitMemory   = "150Mi"
)

func (c *component) cawServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssuranceCAW, Namespace: NameSpaceImageAssurance},
	}
}

func (c *component) cawRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceCAW,
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

func (c *component) cawRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceCAW,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     ResourceNameImageAssuranceCAW,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssuranceCAW,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) cawDeployment() *appsv1.Deployment {

	annots := map[string]string{
		pgConfigHashAnnotation:        rmeta.AnnotationHash(c.config.PGConfig.Data),
		pgUserHashAnnotation:          rmeta.AnnotationHash(c.config.PGUserSecret.Data),
		pgCertsHashAnnotation:         rmeta.AnnotationHash(c.config.PGCertSecret.Data),
		tenantKeySecretHashAnnotation: rmeta.AnnotationHash(c.config.TenantEncryptionKeySecret.Data),
	}

	env := []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_TENANT_ENCRYPTION_KEY", Value: "/tenant-key/encryption_key"},
	}

	env = pgDecorateENVVars(env, PGUserSecretName, MountPathPostgresCerts, PGConfigMapName)

	terminationGracePeriod := int64(30)

	container := corev1.Container{
		Name:            ResourceNameImageAssuranceCAW,
		Image:           c.config.cawImage,
		ImagePullPolicy: corev1.PullAlways,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cawRequestCPU),
				corev1.ResourceMemory: resource.MustParse(cawRequestMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cawLimitCPU),
				corev1.ResourceMemory: resource.MustParse(cawLimitMemory),
			},
		},
		Env: env,
		VolumeMounts: []corev1.VolumeMount{
			{Name: PGCertSecretName, MountPath: MountPathPostgresCerts, ReadOnly: true},
			{Name: TenantEncryptionKeySecretName, MountPath: MountTenantEncryptionKeySecret, ReadOnly: true},
		},
	}

	podSpec := corev1.PodSpec{
		DNSPolicy:                     corev1.DNSClusterFirst,
		ImagePullSecrets:              c.config.Installation.ImagePullSecrets,
		NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
		RestartPolicy:                 corev1.RestartPolicyAlways,
		ServiceAccountName:            ResourceNameImageAssuranceCAW,
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		Containers:                    []corev1.Container{container},
		Volumes:                       c.cawVolumes(),
	}

	replicas := int32(1)
	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceCAW,
			Namespace: NameSpaceImageAssurance,
			Labels: map[string]string{
				"k8s-app": ResourceNameImageAssuranceCAW,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": ResourceNameImageAssuranceCAW,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ResourceNameImageAssuranceCAW,
					Namespace: NameSpaceImageAssurance,
					Labels: map[string]string{
						"k8s-app": ResourceNameImageAssuranceCAW,
					},
					Annotations: annots,
				},
				Spec: podSpec,
			},
		},
	}

	return &d
}

func (c *component) cawVolumes() []corev1.Volume {
	defaultMode := int32(420)

	return []corev1.Volume{
		{
			Name: PGCertSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  PGCertSecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
		{
			Name: TenantEncryptionKeySecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  TenantEncryptionKeySecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
	}
}
