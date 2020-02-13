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
package components

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
	OperatorInitImageName = "tigera/operator-init"
)

// This section contains images used when installing open-source Calico.
const (
	NodeImageNameCalico            = "calico/node"
	CNIImageName                   = "calico/cni"
	TyphaImageNameCalico           = "calico/typha"
	KubeControllersImageNameCalico = "calico/kube-controllers"
	FlexVolumeImageName            = "calico/pod2daemon-flexvol"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	NodeImageNameTigera            = "tigera/cnx-node"
	TyphaImageNameTigera           = "tigera/typha"
	KubeControllersImageNameTigera = "tigera/kube-controllers"

	// API server images.
	APIServerImageName   = "tigera/cnx-apiserver"
	QueryServerImageName = "tigera/cnx-queryserver"

	// Logging
	FluentdImageName = "tigera/fluentd"

	// Compliance images.
	ComplianceControllerImage  = "tigera/compliance-controller"
	ComplianceReporterImage    = "tigera/compliance-reporter"
	ComplianceServerImage      = "tigera/compliance-server"
	ComplianceSnapshotterImage = "tigera/compliance-snapshotter"
	ComplianceBenchmarkerImage = "tigera/compliance-benchmarker"

	// Intrusion detection images.
	IntrusionDetectionControllerImageName   = "tigera/intrusion-detection-controller"
	IntrusionDetectionJobInstallerImageName = "tigera/intrusion-detection-job-installer"

	// Manager images.
	ManagerImageName        = "tigera/cnx-manager"
	ManagerProxyImageName   = "tigera/voltron"
	ManagerEsProxyImageName = "tigera/es-proxy"

	KibanaImageName = "tigera/kibana"

	ECKOperatorImageName      = "eck/eck-operator"
	ECKElasticsearchImageName = "elasticsearch/elasticsearch"
	EsCuratorImageName        = "tigera/es-curator"

	// Multicluster tunnel image.
	GuardianImageName = "tigera/guardian"
)
