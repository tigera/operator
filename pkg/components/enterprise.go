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
		Version: "7.11.2",
		Image:   "tigera/elasticsearch",
	}

	ComponentEckKibana = component{
		Version: "7.11.2",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "master",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "master",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.7.1",
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
		Image:   "tigera/packetcapture-api",
	}

	ComponentL7Collector = component{
		Version: "master",
		Image:   "tigera/l7-collector",
	}

	ComponentEnvoyProxy = component{
		Version: "master",
		Image:   "tigera/envoy",
	}

	ComponentPrometheus = component{
		Version: "v2.17.2",
		Image:   "tigera/prometheus",
	}

	ComponentTigeraPrometheusService = component{
		Version: "master",
		Image:   "tigera/prometheus-service",
	}

	ComponentPrometheusAlertmanager = component{
		Version: "v0.20.0",
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

	ComponentCloudControllers = component{
		Version: "master",
		Image:   "tigera/cloud-controllers",
	}

	ComponentElasticsearchMetrics = component{
		Version: "master",
		Image:   "tigera/elasticsearch-metrics",
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
	}
)
