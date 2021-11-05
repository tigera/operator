// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

var (
	EnterpriseRelease string = "release-calient-v3.11"

	ComponentAPIServer = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentDeepPacketInspection = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/deep-packet-inspection",
	}

	ComponentEckElasticsearch = component{
		Version: "7.11.2",
		Image:   "tigera/elasticsearch",
	}

	ComponentEckKibana = component{
		Version: "7.11.2",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.7.1",
		Image:   "tigera/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/es-proxy",
	}

	ComponentESGateway = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/es-gateway",
	}

	ComponentFluentd = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/fluentd",
	}

	ComponentFluentdWindows = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/fluentd-windows",
	}

	ComponentGuardian = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/dex",
	}

	ComponentManagerProxy = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/voltron",
	}

	ComponentPacketCapture = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/packetcapture-api",
	}

	ComponentL7Collector = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/l7-collector",
	}

	ComponentEnvoyProxy = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/envoy",
	}

	ComponentPrometheus = component{
		Version: "v2.17.2",
		Image:   "tigera/prometheus",
	}

	ComponentTigeraPrometheusService = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/prometheus-service",
	}

	ComponentPrometheusAlertmanager = component{
		Version: "v0.20.0",
		Image:   "tigera/alertmanager",
	}

	ComponentQueryServer = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/cloud-controllers",
	}

	ComponentElasticsearchMetrics = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/elasticsearch-metrics",
	}

	ComponentTigeraWindows = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/calico-windows-upgrade",
	}
	EnterpriseComponents = []component{
		ComponentAPIServer,
		ComponentComplianceBenchmarker,
		ComponentComplianceController,
		ComponentComplianceReporter,
		ComponentComplianceServer,
		ComponentComplianceSnapshotter,
		ComponentDeepPacketInspection,
		ComponentEckElasticsearch,
		ComponentEckKibana,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentEsCurator,
		ComponentEsProxy,
		ComponentFluentd,
		ComponentFluentdWindows,
		ComponentGuardian,
		ComponentIntrusionDetectionController,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentManagerProxy,
		ComponentPacketCapture,
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
		ComponentCloudControllers,
		ComponentElasticsearchMetrics,
		ComponentESGateway,
		ComponentTigeraWindows,
	}
)
