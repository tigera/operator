package render

import (
	"sort"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	VoltronImageAssuranceSecretName = "tigera-image-assurance-api-cert"
	ImageAssuranceCertAnnotation    = "hash.operator.tigera.io/image-assurance-tls"
)

// ManagerCloudResources contains all the resource needed for cloud manager.
type ManagerCloudResources struct {
	ImageAssuranceResources *ImageAssuranceResources
}

// ImageAssuranceResources contains all the resource needed for image assurance.
type ImageAssuranceResources struct {
	TlsSecret *corev1.Secret
}

func (c *managerComponent) decorateCloudVoltronContainer(container corev1.Container) corev1.Container {
	// if image assurance is enabled add env needed for it.
	if c.cfg.ManagerCloudResources.ImageAssuranceResources != nil {
		container.Env = append(container.Env,
			corev1.EnvVar{Name: "VOLTRON_ENABLE_IMAGE_ASSURANCE", Value: "true"},
			corev1.EnvVar{Name: "VOLTRON_IMAGE_ASSURANCE_ENDPOINT", Value: "https://tigera-image-assurance-api.tigera-image-assurance.svc:9443"},
			corev1.EnvVar{Name: "VOLTRON_IMAGE_ASSURANCE_CA_BUNDLE_PATH", Value: "/certs/bast/tls.crt"},
		)
		container.VolumeMounts = append(container.VolumeMounts,
			corev1.VolumeMount{Name: VoltronImageAssuranceSecretName, MountPath: "/certs/bast", ReadOnly: true},
		)
	}
	return container
}

func (c *managerComponent) decorateCloudDeploymentSpec(templateSpec corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	// if image assurance is enabled add env needed for it.
	if c.cfg.ManagerCloudResources.ImageAssuranceResources != nil {
		templateSpec.ObjectMeta.Annotations[ImageAssuranceCertAnnotation] = rmeta.AnnotationHash(c.cfg.ManagerCloudResources.ImageAssuranceResources.TlsSecret.Data)
		templateSpec.Spec.Volumes = append(templateSpec.Spec.Volumes,
			corev1.Volume{
				Name: VoltronImageAssuranceSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						Items: []corev1.KeyToPath{{
							Key:  "tls.crt",
							Path: "tls.crt",
						}},
						SecretName: VoltronImageAssuranceSecretName,
					},
				},
			})
	}
	return templateSpec
}

func (c *managerComponent) addCloudResources(objs []client.Object) []client.Object {
	// if image assurance is enabled add corresponding resources.
	if c.cfg.ManagerCloudResources.ImageAssuranceResources != nil {
		objs = append(objs, secret.ToRuntimeObjects(c.voltronImageAssuranceSecret(c.cfg.ManagerCloudResources.ImageAssuranceResources.TlsSecret))...)
	}

	return objs
}

// Do this as a separate function to try to make updates in the future easier.
func (c *managerComponent) setManagerCloudEnvs(envs []corev1.EnvVar) []corev1.EnvVar {
	envs = append(envs,
		corev1.EnvVar{Name: "ENABLE_MANAGED_CLUSTERS_ONLY", Value: "true"},
		corev1.EnvVar{Name: "LICENSE_EDITION", Value: "cloudEdition"},
	)

	// extra cloud specific env vars needed for image assurance
	if c.cfg.ManagerCloudResources.ImageAssuranceResources != nil {
		envs = append(envs,
			corev1.EnvVar{Name: "ENABLE_IMAGE_ASSURANCE_SUPPORT", Value: "true"},
			corev1.EnvVar{Name: "CNX_IMAGE_ASSURANCE_API_URL", Value: "/bast/v1"},
		)
	}
	// move extra env vars into Manager, but sort them alphabetically first,
	// otherwise, since map iteration is random, they'll be added to the env vars in a random order,
	// which will cause another reconciliation event when Manager is updated.
	sortedKeys := []string{}
	for k := range ManagerExtraEnv {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		val := ManagerExtraEnv[key]
		if key == "portalAPIURL" {
			// support legacy functionality where 'portalAPIURL' was a special field used to set
			// the portal url and enable support.
			envs = append(envs,
				corev1.EnvVar{Name: "CNX_PORTAL_URL", Value: val},
				corev1.EnvVar{Name: "ENABLE_PORTAL_SUPPORT", Value: "true"})
			continue
		}

		if key == "auth0OrgID" {
			// support legacy functionality where 'auth0OrgID' was a special field used to set
			// the org ID
			envs = append(envs, corev1.EnvVar{Name: "CNX_AUTH0_ORG_ID", Value: val})
			continue
		}

		envs = append(envs, corev1.EnvVar{Name: key, Value: val})
	}

	return envs
}

func (c *managerComponent) voltronImageAssuranceSecret(tls *corev1.Secret) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: VoltronImageAssuranceSecretName, Namespace: ManagerNamespace},
		Data: map[string][]byte{
			corev1.TLSCertKey: tls.Data[corev1.TLSCertKey],
		},
	}
}
