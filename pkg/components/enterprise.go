// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

// Components defined here are required to be kept in sync with
// config/enterprise_versions.yml

package components

var (
	EnterpriseRelease string = "master"

	ComponentAPIServer = component{
		Version: "master",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "master",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "master",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "master",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "master",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "master",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentDeepPacketInspection = component{
		Version: "master",
		Image:   "tigera/deep-packet-inspection",
	}

	ComponentEckElasticsearch = component{
		Version: "7.17.7",
	}

	ComponentEckKibana = component{
		Version: "7.17.7",
	}

	ComponentElasticTseeInstaller = component{
		Version: "master",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "master",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchFIPS = component{
		Version: "master-fips",
		Image:   "tigera/elasticsearch",
	}

	ComponentECKElasticsearchOperator = component{
		Version: "2.5.0",
	}

	ComponentElasticsearchOperator = component{
		Version: "master",
		Image:   "tigera/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "master",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "master",
		Image:   "tigera/es-proxy",
	}

	ComponentESGateway = component{
		Version: "master",
		Image:   "tigera/es-gateway",
	}

	ComponentFluentd = component{
		Version: "master",
		Image:   "tigera/fluentd",
	}

	ComponentFluentdWindows = component{
		Version: "master",
		Image:   "tigera/fluentd-windows",
	}

	ComponentGuardian = component{
		Version: "master",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "master",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentAnomalyDetectionJobs = component{
		Version: "master",
		Image:   "tigera/anomaly_detection_jobs",
	}

	ComponentAnomalyDetectionAPI = component{
		Version: "master",
		Image:   "tigera/anomaly-detection-api",
	}

	ComponentKibana = component{
		Version: "master",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "master",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "master",
		Image:   "tigera/dex",
	}

	ComponentManagerProxy = component{
		Version: "master",
		Image:   "tigera/voltron",
	}

	ComponentPacketCapture = component{
		Version: "master",
		Image:   "tigera/packetcapture",
	}

	ComponentEgressGateway = component{
		Version: "master",
		Image:   "tigera/egress-gateway",
	}

	ComponentL7Collector = component{
		Version: "master",
		Image:   "tigera/l7-collector",
	}

	ComponentEnvoyProxy = component{
		Version: "master",
		Image:   "tigera/envoy",
	}

	ComponentDikastes = component{
		Version: "master",
		Image:   "tigera/dikastes",
	}

	ComponentCoreOSPrometheus = component{
		Version: "v2.42.0",
	}

	ComponentPrometheus = component{
		Version: "master",
		Image:   "tigera/prometheus",
	}

	ComponentTigeraPrometheusService = component{
		Version: "master",
		Image:   "tigera/prometheus-service",
	}

	ComponentCoreOSAlertmanager = component{
		Version: "v0.23.0",
	}

	ComponentPrometheusAlertmanager = component{
		Version: "master",
		Image:   "tigera/alertmanager",
	}

	ComponentQueryServer = component{
		Version: "master",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "master",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "master",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "master",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "master",
		Image:   "tigera/cni",
	}

	ComponentTigeraCNIFIPS = component{
		Version: "master-fips",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "master",
		Image:   "tigera/cloud-controllers",
	}

	ComponentElasticsearchMetrics = component{
		Version: "master",
		Image:   "tigera/elasticsearch-metrics",
	}

	ComponentTigeraWindowsUpgrade = component{
		Version: "master",
		Image:   "tigera/calico-windows-upgrade",
	}

	ComponentFlexVolumePrivate = component{
		Version: "master",
		Image:   "tigera/pod2daemon-flexvol",
	}

	ComponentCSIPrivate = component{
		Version: "master",
		Image:   "tigera/csi",
	}

	ComponentCSINodeDriverRegistrarPrivate = component{
		Version: "master",
		Image:   "tigera/node-driver-registrar",
	}
	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	EnterpriseImages = []component{
		ComponentAPIServer,
		ComponentComplianceBenchmarker,
		ComponentComplianceController,
		ComponentComplianceReporter,
		ComponentComplianceServer,
		ComponentComplianceSnapshotter,
		ComponentDeepPacketInspection,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchFIPS,
		ComponentElasticsearchOperator,
		ComponentEsCurator,
		ComponentEsProxy,
		ComponentFluentd,
		ComponentFluentdWindows,
		ComponentGuardian,
		ComponentIntrusionDetectionController,
		ComponentAnomalyDetectionJobs,
		ComponentAnomalyDetectionAPI,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentManagerProxy,
		ComponentPacketCapture,
		ComponentEgressGateway,
		ComponentL7Collector,
		ComponentEnvoyProxy,
		ComponentPrometheus,
		ComponentTigeraPrometheusService,
		ComponentPrometheusAlertmanager,
		ComponentQueryServer,
		ComponentTigeraKubeControllers,
		ComponentTigeraNode,
		ComponentTigeraTypha,
		ComponentTigeraCNI,
		ComponentTigeraCNIFIPS,
		ComponentCloudControllers,
		ComponentElasticsearchMetrics,
		ComponentESGateway,
		ComponentTigeraWindowsUpgrade,
		ComponentDikastes,
		ComponentFlexVolumePrivate,
		ComponentCSIPrivate,
		ComponentCSINodeDriverRegistrarPrivate,
	}
)
