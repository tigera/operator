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
	EnterpriseRelease string = "v3.11.1"

	ComponentAPIServer = component{
		Version: "v3.11.1",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v3.11.1",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v3.11.1",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v3.11.1",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v3.11.1",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v3.11.1",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentDeepPacketInspection = component{
		Version: "v3.11.1",
		Image:   "tigera/deep-packet-inspection",
	}

	ComponentEckElasticsearch = component{
		Version: "7.16.2",
		Image:   "tigera/elasticsearch",
	}

	ComponentEckKibana = component{
		Version: "7.16.2",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v3.11.1",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "v3.11.1",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.8.0",
		Image:   "tigera/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "v3.11.1",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v3.11.1",
		Image:   "tigera/es-proxy",
	}

	ComponentESGateway = component{
		Version: "v3.11.1",
		Image:   "tigera/es-gateway",
	}

	ComponentFluentd = component{
		Version: "v3.11.1",
		Image:   "tigera/fluentd",
	}

	ComponentFluentdWindows = component{
		Version: "v3.11.1",
		Image:   "tigera/fluentd-windows",
	}

	ComponentGuardian = component{
		Version: "v3.11.1",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v3.11.1",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "v3.11.1",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v3.11.1",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "v3.11.1",
		Image:   "tigera/dex",
	}

	ComponentManagerProxy = component{
		Version: "v3.11.1",
		Image:   "tigera/voltron",
	}

	ComponentPacketCapture = component{
		Version: "v3.11.1",
		Image:   "tigera/packetcapture-api",
	}

	ComponentL7Collector = component{
		Version: "v3.11.1",
		Image:   "tigera/l7-collector",
	}

	ComponentEnvoyProxy = component{
		Version: "v3.11.1",
		Image:   "tigera/envoy",
	}

	ComponentCoreOSPrometheus = component{
		Version: "v2.32.0",
		Image:   "tigera/prometheus",
	}

	ComponentPrometheus = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/prometheus",
	}

	ComponentTigeraPrometheusService = component{
		Version: "v3.11.1",
		Image:   "tigera/prometheus-service",
	}

	ComponentCoreOSAlertmanager = component{
		Version: "v0.23.0",
		Image:   "tigera/alertmanager",
	}

	ComponentPrometheusAlertmanager = component{
		Version: "release-calient-v3.11",
		Image:   "tigera/alertmanager",
	}

	ComponentQueryServer = component{
		Version: "v3.11.1",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v3.11.1",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v3.11.1",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v3.11.1",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "v3.11.1",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "v3.11.1",
		Image:   "tigera/cloud-controllers",
	}

	ComponentElasticsearchMetrics = component{
		Version: "v3.11.1",
		Image:   "tigera/elasticsearch-metrics",
	}

	ComponentTigeraWindows = component{
		Version: "v3.11.1",
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
		ComponentCoreOSPrometheus,
		ComponentPrometheus,
		ComponentTigeraPrometheusService,
		ComponentCoreOSAlertmanager,
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
