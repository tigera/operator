package render

import (
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/components"
)

// Default registries for Calico and Tigera.
const (
	CalicoRegistry = "docker.io/"
	TigeraRegistry = "quay.io/"
	K8sGcrRegistry = "gcr.io/"
	ECKRegistry    = "docker.elastic.co/"
)

// This section contains images used for utility operator functions.
const (
	// The version is supplied by the renderer.
	OperatorInitImageName = "tigera/operator-init:"
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
func constructImage(imageName, registry, imagepath string) string {
	// Default the registry based on component.
	// Do this before adjusting the imageName for imagepath
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

	if imagepath != "" {
		imageName = ReplaceImagePath(imageName, imagepath)
	}

	// If a user supplied a registry, use that for all images.
	if registry != "" {
		return fmt.Sprintf("%s%s", registry, imageName)
	}
	return fmt.Sprintf("%s%s", reg, imageName)
}

func ReplaceImagePath(image, imagepath string) string {
	subs := strings.SplitAfterN(image, "/", 2)
	if len(subs) == 2 {
		return fmt.Sprintf("%s/%s", imagepath, subs[1])
	}
	return fmt.Sprintf("%s/%s", imagepath, subs[0])
}
