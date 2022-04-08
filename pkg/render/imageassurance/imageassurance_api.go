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
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	apiRequestCPU    = "0.25"
	apiRequestMemory = "50Mi"
	apiLimitCPU      = "0.75"
	apiLimitMemory   = "150Mi"
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
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
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

func (c component) apiService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": ResourceNameImageAssuranceAPI},
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

	annots := map[string]string{
		pgConfigHashAnnotation:        rmeta.AnnotationHash(c.config.PGConfig.Data),
		pgUserHashAnnotation:          rmeta.AnnotationHash(c.config.PGUserSecret.Data),
		pgCertsHashAnnotation:         rmeta.AnnotationHash(c.config.PGCertSecret.Data),
		managerCertHashAnnotation:     rmeta.AnnotationHash(c.config.InternalMgrSecret.Data),
		tenantKeySecretHashAnnotation: rmeta.AnnotationHash(c.config.TenantEncryptionKeySecret.Data),
		apiCertHashAnnotation:         c.config.tlsHash,
	}

	env := []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_PORT", Value: "5557"},
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_DB_LOG_LEVEL", Value: "SILENT"},
		{Name: "IMAGE_ASSURANCE_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "IMAGE_ASSURANCE_HTTPS_KEY", Value: "/certs/https/tls.key"},
		{Name: "IMAGE_ASSURANCE_TENANT_ENCRYPTION_KEY", Value: "/tenant-key/encryption_key"},
	}

	env = pgDecorateENVVars(env, PGUserSecretName, MountPathPostgresCerts, PGConfigMapName)

	terminationGracePeriod := int64(30)
	privileged := true

	volumeMounts := []corev1.VolumeMount{
		{Name: APICertSecretName, MountPath: mountPathAPITLSCerts, ReadOnly: true},
		{Name: PGCertSecretName, MountPath: MountPathPostgresCerts, ReadOnly: true},
		{Name: ManagerCertSecretName, MountPath: mountPathManagerTLSCerts, ReadOnly: true},
		{Name: TenantEncryptionKeySecretName, MountPath: MountTenantEncryptionKeySecret, ReadOnly: true},
	}

	if c.config.KeyValidatorConfig != nil {
		env = append(env, c.config.KeyValidatorConfig.RequiredEnv("IMAGE_ASSURANCE_")...)
		volumeMounts = append(volumeMounts, c.config.KeyValidatorConfig.RequiredVolumeMounts()...)
	}

	container := corev1.Container{
		Name:            ResourceNameImageAssuranceAPI,
		Image:           c.config.apiImage,
		ImagePullPolicy: corev1.PullAlways,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(apiRequestCPU),
				corev1.ResourceMemory: resource.MustParse(apiRequestMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(apiLimitCPU),
				corev1.ResourceMemory: resource.MustParse(apiLimitMemory),
			},
		},
		Env: env,
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		VolumeMounts: volumeMounts,
	}

	podSpec := corev1.PodSpec{
		DNSPolicy:                     corev1.DNSClusterFirst,
		ImagePullSecrets:              c.config.Installation.ImagePullSecrets,
		NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
		RestartPolicy:                 corev1.RestartPolicyAlways,
		ServiceAccountName:            ResourceNameImageAssuranceAPI,
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		Containers:                    []corev1.Container{container},
		Volumes:                       c.apiVolumes(),
	}
	replicas := int32(1)
	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceAPI,
			Namespace: NameSpaceImageAssurance,
			Labels: map[string]string{
				"k8s-app": ResourceNameImageAssuranceAPI,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": ResourceNameImageAssuranceAPI,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ResourceNameImageAssuranceAPI,
					Namespace: NameSpaceImageAssurance,
					Labels: map[string]string{
						"k8s-app": ResourceNameImageAssuranceAPI,
					},
					Annotations: annots,
				},
				Spec: podSpec,
			},
		},
	}

	return &d
}

func (c *component) apiVolumes() []corev1.Volume {
	defaultMode := int32(420)

	volumes := []corev1.Volume{
		{
			Name: APICertSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  APICertSecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
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
			Name: ManagerCertSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					DefaultMode: &defaultMode,
					Items: []corev1.KeyToPath{
						{
							Key:  "cert",
							Path: "cert",
						},
					},
					SecretName: ManagerCertSecretName,
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

	if c.config.KeyValidatorConfig != nil {
		volumes = append(volumes, c.config.KeyValidatorConfig.RequiredVolumes()...)
	}

	return volumes
}
