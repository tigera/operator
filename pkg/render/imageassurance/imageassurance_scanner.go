// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	scannerRequestCPU    = "250m"
	scannerRequestMemory = "512Mi"
	scannerLimitCPU      = "1"
	scannerLimitMemory   = "1.5Gi"
)

func (c *component) scannerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssuranceScanner, Namespace: NameSpaceImageAssurance},
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

func (c *component) scannerDeployment() *appsv1.Deployment {

	annots := map[string]string{
		pgConfigHashAnnotation: rmeta.AnnotationHash(c.config.PGConfig.Data),
		pgUserHashAnnotation:   rmeta.AnnotationHash(c.config.PGUserSecret.Data),
		pgCertsHashAnnotation:  rmeta.AnnotationHash(c.config.PGCertSecret.Data),
	}

	env := []corev1.EnvVar{
		{Name: "IMAGE_ASSURANCE_LOGLEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_SCANNER_RETRIES", Value: "3"},
	}

	env = pgDecorateENVVars(env, PGUserSecretName, MountPathPostgresCerts, PGConfigMapName)

	terminationGracePeriod := int64(30)
	isPrivileged := true

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
		SecurityContext: &corev1.SecurityContext{
			Privileged: &isPrivileged,
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: PGCertSecretName, MountPath: MountPathPostgresCerts, ReadOnly: true},
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
	}
}
