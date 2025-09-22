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
		ImageName: "apiserver",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentComplianceBenchmarker = Component{
		Version:   "master",
		ImageName: "compliance-benchmarker",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentComplianceController = Component{
		Version:   "master",
		ImageName: "compliance-controller",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentComplianceReporter = Component{
		Version:   "master",
		ImageName: "compliance-reporter",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentComplianceServer = Component{
		Version:   "master",
		ImageName: "compliance-server",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentComplianceSnapshotter = Component{
		Version:   "master",
		ImageName: "compliance-snapshotter",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:   "master",
		ImageName: "key-cert-provisioner",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentDeepPacketInspection = Component{
		Version:   "master",
		ImageName: "deep-packet-inspection",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentEckElasticsearch = Component{
		Version:  "8.18.4",
		Registry: "",
	}

	ComponentEckKibana = Component{
		Version:  "8.18.4",
		Registry: "",
	}

	ComponentElasticTseeInstaller = Component{
		Version:   "master",
		ImageName: "intrusion-detection-job-installer",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentElasticsearch = Component{
		Version:   "master",
		ImageName: "elasticsearch",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentECKElasticsearchOperator = Component{
		Version:  "2.16.0",
		Registry: "",
	}

	ComponentElasticsearchOperator = Component{
		Version:   "master",
		ImageName: "eck-operator",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentUIAPIs = Component{
		Version:   "master",
		ImageName: "ui-apis",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentESGateway = Component{
		Version:   "master",
		ImageName: "es-gateway",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentLinseed = Component{
		Version:   "master",
		ImageName: "linseed",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentFluentd = Component{
		Version:   "master",
		ImageName: "fluentd",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentFluentdWindows = Component{
		Version:   "master",
		ImageName: "fluentd-windows",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentGuardian = Component{
		Version:   "master",
		ImageName: "guardian",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentIntrusionDetectionController = Component{
		Version:   "master",
		ImageName: "intrusion-detection-controller",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentWAFHTTPFilter = Component{
		Version:   "master",
		ImageName: "waf-http-filter",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:   "master",
		ImageName: "webhooks-processor",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentKibana = Component{
		Version:   "master",
		ImageName: "kibana",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentManager = Component{
		Version:   "master",
		ImageName: "manager",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentDex = Component{
		Version:   "master",
		ImageName: "dex",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentManagerProxy = Component{
		Version:   "master",
		ImageName: "voltron",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentPacketCapture = Component{
		Version:   "master",
		ImageName: "packetcapture",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentPolicyRecommendation = Component{
		Version:   "master",
		ImageName: "policy-recommendation",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentEgressGateway = Component{
		Version:   "master",
		ImageName: "egress-gateway",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentL7Collector = Component{
		Version:   "master",
		ImageName: "l7-collector",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentEnvoyProxy = Component{
		Version:   "master",
		ImageName: "envoy",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentDikastes = Component{
		Version:   "master",
		ImageName: "dikastes",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentL7AdmissionController = Component{
		Version:   "master",
		ImageName: "l7-admission-controller",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentCoreOSPrometheus = Component{
		Version:  "v3.4.1",
		Registry: "",
	}

	ComponentPrometheus = Component{
		Version:   "master",
		ImageName: "prometheus",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraPrometheusService = Component{
		Version:   "master",
		ImageName: "prometheus-service",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentCoreOSAlertmanager = Component{
		Version:  "v0.28.0",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = Component{
		Version:   "master",
		ImageName: "alertmanager",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentQueryServer = Component{
		Version:   "master",
		ImageName: "queryserver",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraKubeControllers = Component{
		Version:   "master",
		ImageName: "kube-controllers",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraNode = Component{
		Version:   "master",
		ImageName: "node",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "master",
		ImageName: "node-windows",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraTypha = Component{
		Version:   "master",
		ImageName: "typha",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCNI = Component{
		Version:   "master",
		ImageName: "cni",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "master",
		ImageName: "cni-windows",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentElasticsearchMetrics = Component{
		Version:   "master",
		ImageName: "elasticsearch-metrics",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraFlexVolume = Component{
		Version:   "master",
		ImageName: "pod2daemon-flexvol",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCSI = Component{
		Version:   "master",
		ImageName: "csi",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:   "master",
		ImageName: "node-driver-registrar",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "master",
		ImageName: "envoy-gateway",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "master",
		ImageName: "envoy-proxy",
		ImagePath: TigeraImagePath,
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "master",
		ImageName: "envoy-ratelimit",
		ImagePath: TigeraImagePath,
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
