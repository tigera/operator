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
	DigestCalicoNode             = "{{ (index .Calico "calico/node").Digest }}"
	VersionCalicoCNI             = "{{ (index .Calico "calico/cni").Version }}"
	DigestCalicoCNI              = "{{ (index .Calico "calico/cni").Digest }}"
	VersionCalicoTypha           = "{{ .Calico.typha.Version }}"
	DigestCalicoTypha            = "{{ .Calico.typha.Digest }}"
	VersionCalicoKubeControllers = "{{ (index .Calico "calico/kube-controllers" ).Version }}"
	DigestCalicoKubeControllers  = "{{ (index .Calico "calico/kube-controllers" ).Digest }}"
	VersionFlexVolume            = "{{ .Calico.flexvol.Version }}"
	DigestFlexVolume             = "{{ .Calico.flexvol.Digest }}"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "{{ (index .Enterprise "cnx-node").Version }}"
	DigestTigeraNode             = "{{ (index .Enterprise "cnx-node").Digest }}"
	VersionTigeraTypha           = "{{ .Enterprise.typha.Version }}"
	DigestTigeraTypha            = "{{ .Enterprise.typha.Digest }}"
	VersionTigeraKubeControllers = "{{ (index .Enterprise "cnx-kube-controllers").Version }}"
	DigestTigeraKubeControllers  = "{{ (index .Enterprise "cnx-kube-controllers").Digest }}"

	// API server images.
	VersionAPIServer   = "{{ (index .Enterprise "cnx-apiserver").Version }}"
	DigestAPIServer    = "{{ (index .Enterprise "cnx-apiserver").Digest }}"
	VersionQueryServer = "{{ (index .Enterprise "cnx-queryserver").Version }}"
	DigestQueryServer  = "{{ (index .Enterprise "cnx-queryserver").Digest }}"

	// Logging
	VersionFluentd = "{{ .Enterprise.fluentd.Version }}"
	DigestFluentd  = "{{ .Enterprise.fluentd.Digest }}"

	// Compliance images.
	VersionComplianceController  = "{{ (index .Enterprise "compliance-controller").Version }}"
	DigestComplianceController   = "{{ (index .Enterprise "compliance-controller").Digest }}"
	VersionComplianceReporter    = "{{ (index .Enterprise "compliance-reporter").Version }}"
	DigestComplianceReporter     = "{{ (index .Enterprise "compliance-reporter").Digest }}"
	VersionComplianceServer      = "{{ (index .Enterprise "compliance-server").Version }}"
	DigestComplianceServer       = "{{ (index .Enterprise "compliance-server").Digest }}"
	VersionComplianceSnapshotter = "{{ (index .Enterprise "compliance-snapshotter").Version }}"
	DigestComplianceSnapshotter  = "{{ (index .Enterprise "compliance-snapshotter").Digest }}"
	VersionComplianceBenchmarker = "{{ (index .Enterprise "compliance-benchmarker").Version }}"
	DigestComplianceBenchmarker  = "{{ (index .Enterprise "compliance-benchmarker").Digest }}"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "{{ (index .Enterprise "intrusion-detection-controller").Version }}"
	DigestIntrusionDetectionController    = "{{ (index .Enterprise "intrusion-detection-controller").Digest }}"
	VersionIntrusionDetectionJobInstaller = "{{ (index .Enterprise "elastic-tsee-installer").Version }}"
	DigestIntrusionDetectionJobInstaller  = "{{ (index .Enterprise "elastic-tsee-installer").Digest }}"

	// Manager images.
	VersionManager        = "{{ (index .Enterprise "cnx-manager").Version }}"
	DigestManager         = "{{ (index .Enterprise "cnx-manager").Digest }}"
	VersionManagerProxy   = "{{ .Enterprise.voltron.Version }}"
	DigestManagerProxy    = "{{ .Enterprise.voltron.Digest }}"
	VersionManagerEsProxy = "{{ (index .Enterprise "es-proxy").Version }}"
	DigestManagerEsProxy  = "{{ (index .Enterprise "es-proxy").Digest }}"

	// ECK Elasticsearch images
	VersionECKOperator      = "{{ (index .Enterprise "elasticsearch-operator").Version }}"
	DigestECKOperator       = "{{ (index .Enterprise "elasticsearch-operator").Digest }}"
	VersionECKElasticsearch = "{{ .Enterprise.elasticsearch.Version }}"
	DigestECKElasticsearch  = "{{ .Enterprise.elasticsearch.Digest }}"
	VersionECKKibana        = "{{ (index .Enterprise "eck-kibana").Version }}"
	DigestECKKibana         = "{{ (index .Enterprise "eck-kibana").Digest }}"
	VersionEsCurator        = "{{ (index .Enterprise "es-curator").Version }}"
	DigestEsCurator         = "{{ (index .Enterprise "es-curator").Digest }}"

	VersionKibana = "{{ .Enterprise.kibana.Version }}"
	DigestKibana  = "{{ .Enterprise.kibana.Digest }}"

	// Multicluster tunnel image.
	VersionGuardian = "{{ .Enterprise.guardian.Version }}"
	DigestGuardian  = "{{ .Enterprise.guardian.Digest }}"
)
