// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	// Multicluster tunnel image.
	GuardianImageName = "tigera/guardian:" + components.VersionGuardian
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
