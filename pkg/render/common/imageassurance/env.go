package imageassurance

import (
	"github.com/tigera/operator/pkg/render/common/configmap"
	corev1 "k8s.io/api/core/v1"
)

func EnvOrganizationID() corev1.EnvVar {
	return corev1.EnvVar{
		Name: "IMAGE_ASSURANCE_ORGANIZATION_ID",
		ValueFrom: configmap.GetEnvVarSource(
			ConfigurationConfigMapName, ConfigurationConfigMapOrgIDKey, false),
	}
}
