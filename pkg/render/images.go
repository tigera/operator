package render

import (
	"fmt"

	"github.com/tigera/operator/pkg/components"
)

// Default registries for Calico and Tigera.
const (
	CalicoRegistry = "docker.io/calico/"
	TigeraRegistry = "quay.io/tigera/"
	K8sGcrRegistry = "gcr.io/google-containers/"
)

// This section contains images used when installing open-source Calico.
const (
	NodeImageNameCalico            = "node:" + components.VersionCalicoNode
	CNIImageName                   = "cni:" + components.VersionCalicoCNI
	TyphaImageNameCalico           = "typha:" + components.VersionCalicoTypha
	KubeControllersImageNameCalico = "kube-controllers:" + components.VersionCalicoKubeControllers
	FlexVolumeImageName            = "pod2daemon-flexvol:" + components.VersionFlexVolume
	HorizontalAutoScalerImageName  = "cluster-proportional-autoscaler-amd64:" + components.VersionCPHAutoscaler
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	NodeImageNameTigera            = "cnx-node:" + components.VersionTigeraNode
	TyphaImageNameTigera           = "typha:" + components.VersionTigeraTypha
	KubeControllersImageNameTigera = "kube-controllers:" + components.VersionTigeraKubeControllers

	// API server images.
	APIServerImageName   = "cnx-apiserver:" + components.VersionAPIServer
	QueryServerImageName = "cnx-queryserver:" + components.VersionQueryServer

	// Compliance images.
	ComplianceControllerImage  = "compliance-controller:" + components.VersionComplianceController
	ComplianceReporterImage    = "compliance-reporter:" + components.VersionComplianceReporter
	ComplianceServerImage      = "compliance-server:" + components.VersionComplianceServer
	ComplianceSnapshotterImage = "compliance-snapshotter:" + components.VersionComplianceSnapshotter
	ComplianceBenchmarkerImage = "compliance-benchmarker:" + components.VersionComplianceBenchmarker

	// Intrusion detection images.
	IntrusionDetectionControllerImageName   = "intrusion-detection-controller:" + components.VersionIntrusionDetectionController
	IntrusionDetectionJobInstallerImageName = "intrusion-detection-job-installer:" + components.VersionIntrusionDetectionJobInstaller

	// Console images.
	ConsoleManagerImageName = "cnx-manager:" + components.VersionConsoleManager
	ConsoleProxyImageName   = "cnx-manager-proxy:" + components.VersionConsoleProxy
	ConsoleEsProxyImageName = "es-proxy:" + components.VersionConsoleEsProxy
)

// constructImage returns the fully qualified image to use, including registry and version.
func constructImage(imageName string, registry string) string {
	// If a user supplied a registry, use that for all images.
	if registry != "" {
		return fmt.Sprintf("%s%s", registry, imageName)
	}

	// Otherwise, default the registry based on component.
	reg := TigeraRegistry
	switch imageName {
	case NodeImageNameCalico,
		CNIImageName,
		TyphaImageNameCalico,
		KubeControllersImageNameCalico,
		FlexVolumeImageName:

		reg = CalicoRegistry
	case HorizontalAutoScalerImageName:
		reg = K8sGcrRegistry
	}
	return fmt.Sprintf("%s%s", reg, imageName)
}
