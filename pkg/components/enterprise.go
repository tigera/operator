// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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

	ComponentAPIServer = Component{
		Version:   "master",
		Image:     "apiserver",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentComplianceBenchmarker = Component{
		Version:  "master",
		Image:    "compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = Component{
		Version:  "master",
		Image:    "compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = Component{
		Version:  "master",
		Image:    "compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = Component{
		Version:  "master",
		Image:    "compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = Component{
		Version:  "master",
		Image:    "compliance-snapshotter",
		Registry: "",
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:   "master",
		Image:     "key-cert-provisioner",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentDeepPacketInspection = Component{
		Version:  "master",
		Image:    "deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = Component{
		Version: "8.18.4",
	}

	ComponentEckKibana = Component{
		Version: "8.18.4",
	}

	ComponentElasticTseeInstaller = Component{
		Version:  "master",
		Image:    "intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = Component{
		Version:  "master",
		Image:    "elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = Component{
		Version: "2.16.0",
	}

	ComponentElasticsearchOperator = Component{
		Version:  "master",
		Image:    "eck-operator",
		Registry: "",
	}

	ComponentUIAPIs = Component{
		Version:  "master",
		Image:    "ui-apis",
		Registry: "",
	}

	ComponentESGateway = Component{
		Version:  "master",
		Image:    "es-gateway",
		Registry: "",
	}

	ComponentLinseed = Component{
		Version:  "master",
		Image:    "linseed",
		Registry: "",
	}

	ComponentFluentd = Component{
		Version:  "master",
		Image:    "fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = Component{
		Version:  "master",
		Image:    "fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = Component{
		Version:   "master",
		Image:     "guardian",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentIntrusionDetectionController = Component{
		Version:  "master",
		Image:    "intrusion-detection-controller",
		Registry: "",
	}

	ComponentWAFHTTPFilter = Component{
		Version:  "master",
		Image:    "waf-http-filter",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:  "master",
		Image:    "webhooks-processor",
		Registry: "",
	}

	ComponentKibana = Component{
		Version:  "master",
		Image:    "kibana",
		Registry: "",
	}

	ComponentManager = Component{
		Version:  "master",
		Image:    "manager",
		Registry: "",
	}

	ComponentDex = Component{
		Version:  "master",
		Image:    "dex",
		Registry: "",
	}

	ComponentManagerProxy = Component{
		Version:  "master",
		Image:    "voltron",
		Registry: "",
	}

	ComponentPacketCapture = Component{
		Version:  "master",
		Image:    "packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = Component{
		Version:  "master",
		Image:    "policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = Component{
		Version:  "master",
		Image:    "egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = Component{
		Version:  "master",
		Image:    "l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = Component{
		Version:  "master",
		Image:    "envoy",
		Registry: "",
	}

	ComponentDikastes = Component{
		Version:  "master",
		Image:    "dikastes",
		Registry: "",
	}

	ComponentL7AdmissionController = Component{
		Version:  "master",
		Image:    "l7-admission-controller",
		Registry: "",
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.4.1",
	}

	ComponentPrometheus = Component{
		Version:  "master",
		Image:    "prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = Component{
		Version:  "master",
		Image:    "prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.28.0",
	}

	ComponentPrometheusAlertmanager = Component{
		Version:  "master",
		Image:    "alertmanager",
		Registry: "",
	}

	ComponentQueryServer = Component{
		Version:  "master",
		Image:    "queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = Component{
		Version:   "master",
		Image:     "kube-controllers",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraNode = Component{
		Version:   "master",
		Image:     "node",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "master",
		Image:     "node-windows",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraTypha = Component{
		Version:   "master",
		Image:     "typha",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCNI = Component{
		Version:   "master",
		Image:     "cni",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "master",
		Image:     "cni-windows",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentElasticsearchMetrics = Component{
		Version:  "master",
		Image:    "elasticsearch-metrics",
		Registry: "",
	}

	ComponentTigeraFlexVolume = Component{
		Version:   "master",
		Image:     "pod2daemon-flexvol",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCSI = Component{
		Version:   "master",
		Image:     "csi",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:   "master",
		Image:     "node-driver-registrar",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "master",
		Image:     "envoy-gateway",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "master",
		Image:     "envoy-proxy",
		imagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "master",
		Image:     "envoy-ratelimit",
		imagePath: TigeraImagePath,
		Registry:  "",
	}
	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	EnterpriseImages = []Component{
		ComponentAPIServer,
		ComponentComplianceBenchmarker,
		ComponentComplianceController,
		ComponentComplianceReporter,
		ComponentComplianceServer,
		ComponentComplianceSnapshotter,
		ComponentTigeraCSRInitContainer,
		ComponentDeepPacketInspection,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentUIAPIs,
		ComponentFluentd,
		ComponentFluentdWindows,
		ComponentGuardian,
		ComponentIntrusionDetectionController,
		ComponentWAFHTTPFilter,
		ComponentSecurityEventWebhooksProcessor,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentManagerProxy,
		ComponentPacketCapture,
		ComponentPolicyRecommendation,
		ComponentEgressGateway,
		ComponentL7Collector,
		ComponentEnvoyProxy,
		ComponentPrometheus,
		ComponentTigeraPrometheusService,
		ComponentPrometheusAlertmanager,
		ComponentQueryServer,
		ComponentTigeraKubeControllers,
		ComponentTigeraNode,
		ComponentTigeraNodeWindows,
		ComponentTigeraTypha,
		ComponentTigeraCNI,
		ComponentTigeraCNIWindows,
		ComponentElasticsearchMetrics,
		ComponentESGateway,
		ComponentLinseed,
		ComponentDikastes,
		ComponentL7AdmissionController,
		ComponentTigeraFlexVolume,
		ComponentTigeraCSI,
		ComponentTigeraCSINodeDriverRegistrar,
		ComponentGatewayAPIEnvoyGateway,
		ComponentGatewayAPIEnvoyProxy,
		ComponentGatewayAPIEnvoyRatelimit,
	}
)
