package render

import (
	"fmt"

	"github.com/tigera/operator/pkg/components"
)

// Default registries for Calico and Tigera.
const (
	CalicoRegistry           = "docker.io/calico/"
	TigeraRegistry           = "gcr.io/unique-caldron-775/cnx/tigera/"
	K8sGcrRegistry           = "gcr.io/google-containers/"
	ECKOperatorRegistry      = "docker.elastic.co/eck/"
	ECKElasticsearchRegistry = "docker.elastic.co/elasticsearch/"
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

	// Logging
	FluentdImageName = "fluentd:" + components.VersionFluentd

	// Compliance images.
	ComplianceControllerImage  = "compliance-controller:" + components.VersionComplianceController
	ComplianceReporterImage    = "compliance-reporter:" + components.VersionComplianceReporter
	ComplianceServerImage      = "compliance-server:" + components.VersionComplianceServer
	ComplianceSnapshotterImage = "compliance-snapshotter:" + components.VersionComplianceSnapshotter
	ComplianceBenchmarkerImage = "compliance-benchmarker:" + components.VersionComplianceBenchmarker

	// Intrusion detection images.
	IntrusionDetectionControllerImageName   = "intrusion-detection-controller:" + components.VersionIntrusionDetectionController
	IntrusionDetectionJobInstallerImageName = "intrusion-detection-job-installer:" + components.VersionIntrusionDetectionJobInstaller

	// Manager images.
	ManagerImageName        = "cnx-manager:" + components.VersionManager
	ManagerProxyImageName   = "voltron:" + components.VersionManagerProxy
	ManagerEsProxyImageName = "es-proxy:" + components.VersionManagerEsProxy

	ECKOperatorImageName      = "eck-operator:" + components.VersionECKOperator
	ECKElasticsearchImageName = "elasticsearch:" + components.VersionECKElasticsearch
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
	case ECKElasticsearchImageName:
		reg = ECKElasticsearchRegistry
	case ECKOperatorImageName:
		reg = ECKOperatorRegistry
	}
	return fmt.Sprintf("%s%s", reg, imageName)
}
