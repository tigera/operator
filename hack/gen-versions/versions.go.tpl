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

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "{{ (index .Calico "calico/node").Version }}"
	VersionCalicoCNI             = "{{ (index .Calico "calico/cni").Version }}"
	VersionCalicoTypha           = "{{ .Calico.typha.Version }}"
	VersionCalicoKubeControllers = "{{ (index .Calico "calico/kube-controllers" ).Version }}"
	VersionFlexVolume            = "{{ .Calico.flexvol.Version }}"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "{{ (index .Enterprise "cnx-node").Version }}"
	VersionTigeraTypha           = "{{ .Enterprise.typha.Version }}"
	VersionTigeraKubeControllers = "{{ (index .Enterprise "cnx-kube-controllers").Version }}"

	// API server images.
	VersionAPIServer   = "{{ (index .Enterprise "cnx-apiserver").Version }}"
	VersionQueryServer = "{{ (index .Enterprise "cnx-queryserver").Version }}"

	// Logging
	VersionFluentd = "{{ .Enterprise.fluentd.Version }}"

	// Compliance images.
	VersionComplianceController  = "{{ (index .Enterprise "compliance-controller").Version }}"
	VersionComplianceReporter    = "{{ (index .Enterprise "compliance-reporter").Version }}"
	VersionComplianceServer      = "{{ (index .Enterprise "compliance-server").Version }}"
	VersionComplianceSnapshotter = "{{ (index .Enterprise "compliance-snapshotter").Version }}"
	VersionComplianceBenchmarker = "{{ (index .Enterprise "compliance-benchmarker").Version }}"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "{{ (index .Enterprise "intrusion-detection-controller").Version }}"
	VersionIntrusionDetectionJobInstaller = "{{ (index .Enterprise "elastic-tsee-installer").Version }}"

	// Manager images.
	VersionManager        = "{{ (index .Enterprise "cnx-manager").Version }}"
	VersionManagerProxy   = "{{ .Enterprise.voltron.Version }}"
	VersionManagerEsProxy = "{{ (index .Enterprise "es-proxy").Version }}"

	// ECK Elasticsearch images
	VersionECKOperator      = "{{ (index .Enterprise "elasticsearch-operator").Version }}"
	VersionECKElasticsearch = "{{ .Enterprise.elasticsearch.Version }}"
	VersionECKKibana        = "{{ (index .Enterprise "eck-kibana").Version }}"
	VersionEsCurator        = "{{ (index .Enterprise "es-curator").Version }}"

	VersionKibana = "{{ .Enterprise.kibana.Version }}"

	// Multicluster tunnel image.
	VersionGuardian = "{{ .Enterprise.guardian.Version }}"
)
