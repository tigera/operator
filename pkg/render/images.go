package render

import (
	"fmt"
)

// Default registries for Calico and Tigera.
const (
	CalicoRegistry = "docker.io/calico/"
	TigeraRegistry = "quay.io/tigera/"
)

// This section contains images used when installing open-source Calico.
const (
	NodeImageNameCalico            = "node:v3.8.1"
	CNIImageName                   = "cni:v3.8.1"
	KubeControllersImageNameCalico = "kube-controllers:v3.8.1"
	FlexVolumeImageName            = "pod2daemon-flexvol:v3.8.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	NodeImageNameTigera            = "cnx-node:nft-1fd1d3"
	KubeControllersImageNameTigera = "kube-controllers:v2.4.2"

	// API server images.
	APIServerImageName   = "cnx-apiserver:v2.4.0"
	QueryServerImageName = "cnx-queryserver:v2.4.0"

	// Compliance images.
	ComplianceControllerImage  = "compliance-controller:v2.4.2"
	ComplianceReporterImage    = "compliance-reporter:v2.4.2"
	ComplianceServerImage      = "compliance-server:v2.4.2"
	ComplianceSnapshotterImage = "compliance-snapshotter:v2.4.2"
	ComplianceBenchmarkerImage = "compliance-benchmarker:v2.5.0"

	// Intrusion detection images.
	IntrusionDetectionControllerImageName   = "intrusion-detection-controller:v2.4.2"
	IntrusionDetectionJobInstallerImageName = "intrusion-detection-job-installer:v2.4.2"

	// Console images.
	ConsoleManagerImageName = "cnx-manager:v2.4.2"
	ConsoleProxyImageName   = "cnx-manager-proxy:v2.4.2"
	ConsoleEsProxyImageName = "es-proxy:v2.4.0"
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
	case NodeImageNameCalico, CNIImageName, KubeControllersImageNameCalico, FlexVolumeImageName:
		reg = CalicoRegistry
	}
	return fmt.Sprintf("%s%s", reg, imageName)
}
