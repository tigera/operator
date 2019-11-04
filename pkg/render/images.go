package render

import (
	"fmt"

	"github.com/tigera/operator/pkg/components"
)

// Default registries for Calico and Tigera.
const (
	CalicoRegistry = "docker.io/"
	TigeraRegistry = "gcr.io/unique-caldron-775/cnx/"
	K8sGcrRegistry = "gcr.io/"
	ECKRegistry    = "docker.elastic.co/"
)

// This section contains images used for utility operator functions.
const (
	// The version will be added to this image by the render'er using
	// it. This is an abnormal one off and should be fixed/resolved
	// soon.
	OperatorInitImageName = "operator-init:"
)

// This section contains images used when installing open-source Calico.
const (
	NodeImageNameCalico            = "calico/node:" + components.VersionCalicoNode
	CNIImageName                   = "calico/cni:" + components.VersionCalicoCNI
	TyphaImageNameCalico           = "calico/typha:" + components.VersionCalicoTypha
	KubeControllersImageNameCalico = "calico/kube-controllers:" + components.VersionCalicoKubeControllers
	FlexVolumeImageName            = "calico/pod2daemon-flexvol:" + components.VersionFlexVolume
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	NodeImageNameTigera            = "tigera/cnx-node:" + components.VersionTigeraNode
	TyphaImageNameTigera           = "tigera/typha:" + components.VersionTigeraTypha
	KubeControllersImageNameTigera = "tigera/kube-controllers:" + components.VersionTigeraKubeControllers

	// API server images.
	APIServerImageName   = "tigera/cnx-apiserver:" + components.VersionAPIServer
	QueryServerImageName = "tigera/cnx-queryserver:" + components.VersionQueryServer

	// Logging
	FluentdImageName = "tigera/fluentd:" + components.VersionFluentd

	// Compliance images.
	ComplianceControllerImage  = "tigera/compliance-controller:" + components.VersionComplianceController
	ComplianceReporterImage    = "tigera/compliance-reporter:" + components.VersionComplianceReporter
	ComplianceServerImage      = "tigera/compliance-server:" + components.VersionComplianceServer
	ComplianceSnapshotterImage = "tigera/compliance-snapshotter:" + components.VersionComplianceSnapshotter
	ComplianceBenchmarkerImage = "tigera/compliance-benchmarker:" + components.VersionComplianceBenchmarker

	// Intrusion detection images.
	IntrusionDetectionControllerImageName   = "tigera/intrusion-detection-controller:" + components.VersionIntrusionDetectionController
	IntrusionDetectionJobInstallerImageName = "tigera/intrusion-detection-job-installer:" + components.VersionIntrusionDetectionJobInstaller

	// Manager images.
	ManagerImageName        = "tigera/cnx-manager:" + components.VersionManager
	ManagerProxyImageName   = "tigera/voltron:" + components.VersionManagerProxy
	ManagerEsProxyImageName = "tigera/es-proxy:" + components.VersionManagerEsProxy

	KibanaImageName = "tigera/kibana:" + components.VersionKibana

	ECKOperatorImageName      = "eck/eck-operator:" + components.VersionECKOperator
	ECKElasticsearchImageName = "elasticsearch/elasticsearch:" + components.VersionECKElasticsearch
	EsCuratorImageName        = "tigera/es-curator:" + components.VersionEsCurator
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
	case ECKElasticsearchImageName, ECKOperatorImageName:
		reg = ECKRegistry
	}
	return fmt.Sprintf("%s%s", reg, imageName)
}
