package kubecontrollers

import (
	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	"github.com/tigera/operator/pkg/render/imageassurance"
)

type CloudConfig struct {
	ImageAssurance *operatorv1.ImageAssurance
}

func cloudEnabledControllers(cfg *KubeControllersConfiguration) []string {
	var enabledControllers []string
	if cfg.CloudConfig.ImageAssurance != nil {
		enabledControllers = append(enabledControllers, "imageassurance")
	}

	return enabledControllers
}

func (c *kubeControllersComponent) cloudDecorateContainer(container corev1.Container) corev1.Container {
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise && c.kubeControllerName == EsKubeController &&
		c.cfg.CloudConfig.ImageAssurance != nil {
		container.Env = append(container.Env,
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_ADMISSION_CONTROLLER_CLUSTER_ROLE_NAME", Value: imageassurance.AdmissionControllerAPIClusterRoleName},
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_INTRUSION_DETECTION_CONTROLLER_CLUSTER_ROLE_NAME", Value: render.IntrusionDetectionControllerImageAssuranceAPIClusterRoleName},
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_SCANNER_CLUSTER_ROLE_NAME", Value: imageassurance.ScannerClusterRoleName},
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_SCANNER_CLI_CLUSTER_ROLE_NAME", Value: imageassurance.ScannerCLIClusterRoleName},
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_SCANNER_CLI_TOKEN_SECRET_NAME", Value: rcimageassurance.ScannerCLITokenSecretName},
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_POD_WATCHER_CLUSTER_ROLE_NAME", Value: imageassurance.PodWatcherClusterRoleName},
		)
	}

	return container
}
