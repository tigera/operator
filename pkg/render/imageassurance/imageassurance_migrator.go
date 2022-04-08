package imageassurance

import (
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	migratorRequestCPU    = "0.25"
	migratorRequestMemory = "50Mi"
	migratorLimitCPU      = "0.75"
	migratorLimitMemory   = "150Mi"
)

func (c *component) migratorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: rbacv1.ServiceAccountKind, APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ResourceNameImageAssuranceDBMigrator, Namespace: NameSpaceImageAssurance},
	}
}

func (c *component) migratorRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceDBMigrator,
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

func (c *component) migratorRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceDBMigrator,
			Namespace: NameSpaceImageAssurance,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     ResourceNameImageAssuranceDBMigrator,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      ResourceNameImageAssuranceDBMigrator,
				Namespace: NameSpaceImageAssurance,
			},
		},
	}
}

func (c *component) migratorJob() *batchv1.Job {
	annots := map[string]string{
		pgConfigHashAnnotation:    rmeta.AnnotationHash(c.config.PGConfig.Data),
		pgUserHashAnnotation:      rmeta.AnnotationHash(c.config.PGUserSecret.Data),
		pgCertsHashAnnotation:     rmeta.AnnotationHash(c.config.PGCertSecret.Data),
		pgAdminUserHashAnnotation: rmeta.AnnotationHash(c.config.PGAdminUserSecret.Data),
	}

	env := []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_DB_LOG_LEVEL", Value: "SILENT"},
		{
			Name:      "IMAGE_ASSURANCE_ORGANIZATION_NAME",
			ValueFrom: configmap.GetEnvVarSource(PGConfigMapName, PGConfigOrgNameKey, false),
		},
		{
			Name:      "IMAGE_ASSURANCE_TENANT_USER_NAME",
			ValueFrom: secret.GetEnvVarSource(PGUserSecretName, PGUserSecretKey, false),
		},
		{
			Name:      "IMAGE_ASSURANCE_TENANT_PASSWORD",
			ValueFrom: secret.GetEnvVarSource(PGUserSecretName, PGUserPassKey, false),
		},
	}

	env = pgDecorateENVVars(env, PGAdminUserSecretName, MountPathPostgresCerts, PGConfigMapName)

	container := corev1.Container{
		Name:            ResourceNameImageAssuranceDBMigrator,
		Image:           c.config.migratorImage,
		ImagePullPolicy: corev1.PullAlways,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(migratorRequestCPU),
				corev1.ResourceMemory: resource.MustParse(migratorRequestMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(migratorLimitCPU),
				corev1.ResourceMemory: resource.MustParse(migratorLimitMemory),
			},
		},
		Env: env,
		VolumeMounts: []corev1.VolumeMount{
			{Name: PGCertSecretName, MountPath: MountPathPostgresCerts, ReadOnly: true},
		},
	}

	podSpec := corev1.PodSpec{
		DNSPolicy:                     corev1.DNSClusterFirst,
		ImagePullSecrets:              c.config.Installation.ImagePullSecrets,
		NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
		ServiceAccountName:            ResourceNameImageAssuranceDBMigrator,
		TerminationGracePeriodSeconds: ptr.Int64ToPtr(20),
		Containers:                    []corev1.Container{container},
		Volumes:                       c.migratorVolumes(),
		RestartPolicy:                 corev1.RestartPolicyNever,
	}

	backoffLimit := int32(3)
	j := batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceDBMigrator,
			Namespace: NameSpaceImageAssurance,
			Labels: map[string]string{
				"k8s-app": ResourceNameImageAssuranceDBMigrator,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ResourceNameImageAssuranceDBMigrator,
					Namespace: NameSpaceImageAssurance,
					Labels: map[string]string{
						"k8s-app": ResourceNameImageAssuranceDBMigrator,
					},
					Annotations: annots,
				},
				Spec: podSpec,
			},
		},
	}

	return &j
}

func (c *component) migratorVolumes() []corev1.Volume {
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
