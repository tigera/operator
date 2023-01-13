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
	EnterpriseRelease string = "v3.15.0"

	ComponentAPIServer = component{
		Version: "v3.15.0",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v3.15.0",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v3.15.0",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v3.15.0",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v3.15.0",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v3.15.0",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentDeepPacketInspection = component{
		Version: "v3.15.0",
		Image:   "tigera/deep-packet-inspection",
	}

	ComponentEckElasticsearch = component{
		Version: "7.17.7",
	}

	ComponentEckKibana = component{
		Version: "7.17.7",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v3.15.0",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "v3.15.0",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchFIPS = component{
		Version: "v3.15.0-fips",
		Image:   "tigera/elasticsearch",
	}

	ComponentECKElasticsearchOperator = component{
		Version: "2.5.0",
	}

	ComponentElasticsearchOperator = component{
		Version: "v3.15.0",
		Image:   "tigera/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "v3.15.0",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v3.15.0",
		Image:   "tigera/es-proxy",
	}

	ComponentESGateway = component{
		Version: "v3.15.0",
		Image:   "tigera/es-gateway",
	}

	ComponentFluentd = component{
		Version: "v3.15.0",
		Image:   "tigera/fluentd",
	}

	ComponentFluentdWindows = component{
		Version: "v3.15.0",
		Image:   "tigera/fluentd-windows",
	}

	ComponentGuardian = component{
		Version: "v3.15.0",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v3.15.0",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentAnomalyDetectionJobs = component{
		Version: "v3.15.0",
		Image:   "tigera/anomaly_detection_jobs",
	}

	ComponentAnomalyDetectionAPI = component{
		Version: "v3.15.0",
		Image:   "tigera/anomaly-detection-api",
	}

	ComponentKibana = component{
		Version: "v3.15.0",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v3.15.0",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "v3.15.0",
		Image:   "tigera/dex",
	}

	ComponentManagerProxy = component{
		Version: "v3.15.0",
		Image:   "tigera/voltron",
	}

	ComponentPacketCapture = component{
		Version: "v3.15.0",
		Image:   "tigera/packetcapture",
	}

	ComponentEgressGateway = component{
		Version: "v3.15.0",
		Image:   "tigera/egress-gateway",
	}

	ComponentL7Collector = component{
		Version: "v3.15.0",
		Image:   "tigera/l7-collector",
	}

	ComponentEnvoyProxy = component{
		Version: "v3.15.0",
		Image:   "tigera/envoy",
	}

	ComponentDikastes = component{
		Version: "v3.15.0",
		Image:   "tigera/dikastes",
	}

	ComponentCoreOSPrometheus = component{
		Version: "v2.32.0",
	}

	ComponentPrometheus = component{
		Version: "v3.15.0",
		Image:   "tigera/prometheus",
	}

	ComponentTigeraPrometheusService = component{
		Version: "v3.15.0",
		Image:   "tigera/prometheus-service",
	}

	ComponentCoreOSAlertmanager = component{
		Version: "v0.23.0",
	}

	ComponentPrometheusAlertmanager = component{
		Version: "v3.15.0",
		Image:   "tigera/alertmanager",
	}

	ComponentQueryServer = component{
		Version: "v3.15.0",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v3.15.0",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v3.15.0",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v3.15.0",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "v3.15.0",
		Image:   "tigera/cni",
	}

	ComponentTigeraCNIFIPS = component{
		Version: "v3.15.0-fips",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "v3.15.0",
		Image:   "tigera/cloud-controllers",
	}

	ComponentElasticsearchMetrics = component{
		Version: "v3.15.0",
		Image:   "tigera/elasticsearch-metrics",
	}

	ComponentTigeraWindowsUpgrade = component{
		Version: "v3.15.0",
		Image:   "tigera/calico-windows-upgrade",
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
	}
)
