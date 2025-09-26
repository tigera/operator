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
		Registry:  "",
	}

	ComponentComplianceBenchmarker = Component{
		Version:   "master",
		ImageName: "compliance-benchmarker",
		Registry:  "",
	}

	ComponentComplianceController = Component{
		Version:   "master",
		ImageName: "compliance-controller",
		Registry:  "",
	}

	ComponentComplianceReporter = Component{
		Version:   "master",
		ImageName: "compliance-reporter",
		Registry:  "",
	}

	ComponentComplianceServer = Component{
		Version:   "master",
		ImageName: "compliance-server",
		Registry:  "",
	}

	ComponentComplianceSnapshotter = Component{
		Version:   "master",
		ImageName: "compliance-snapshotter",
		Registry:  "",
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:   "master",
		ImageName: "key-cert-provisioner",
		Registry:  "",
	}

	ComponentDeepPacketInspection = Component{
		Version:   "master",
		ImageName: "deep-packet-inspection",
		Registry:  "",
	}

	ComponentEckElasticsearch = Component{
		Version: "8.18.4",
	}

	ComponentEckKibana = Component{
		Version: "8.18.4",
	}

	ComponentElasticTseeInstaller = Component{
		Version:   "master",
		ImageName: "intrusion-detection-job-installer",
		Registry:  "",
	}

	ComponentElasticsearch = Component{
		Version:   "master",
		ImageName: "elasticsearch",
		Registry:  "",
	}

	ComponentECKElasticsearchOperator = Component{
		Version: "2.16.0",
	}

	ComponentElasticsearchOperator = Component{
		Version:   "master",
		ImageName: "eck-operator",
		Registry:  "",
	}

	ComponentUIAPIs = Component{
		Version:   "master",
		ImageName: "ui-apis",
		Registry:  "",
	}

	ComponentESGateway = Component{
		Version:   "master",
		ImageName: "es-gateway",
		Registry:  "",
	}

	ComponentLinseed = Component{
		Version:   "master",
		ImageName: "linseed",
		Registry:  "",
	}

	ComponentFluentd = Component{
		Version:   "master",
		ImageName: "fluentd",
		Registry:  "",
	}

	ComponentFluentdWindows = Component{
		Version:   "master",
		ImageName: "fluentd-windows",
		Registry:  "",
	}

	ComponentGuardian = Component{
		Version:   "master",
		ImageName: "guardian",
		Registry:  "",
	}

	ComponentIntrusionDetectionController = Component{
		Version:   "master",
		ImageName: "intrusion-detection-controller",
		Registry:  "",
	}

	ComponentWAFHTTPFilter = Component{
		Version:   "master",
		ImageName: "waf-http-filter",
		Registry:  "",
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:   "master",
		ImageName: "webhooks-processor",
		Registry:  "",
	}

	ComponentKibana = Component{
		Version:   "master",
		ImageName: "kibana",
		Registry:  "",
	}

	ComponentManager = Component{
		Version:   "master",
		ImageName: "manager",
		Registry:  "",
	}

	ComponentDex = Component{
		Version:   "master",
		ImageName: "dex",
		Registry:  "",
	}

	ComponentManagerProxy = Component{
		Version:   "master",
		ImageName: "voltron",
		Registry:  "",
	}

	ComponentPacketCapture = Component{
		Version:   "master",
		ImageName: "packetcapture",
		Registry:  "",
	}

	ComponentPolicyRecommendation = Component{
		Version:   "master",
		ImageName: "policy-recommendation",
		Registry:  "",
	}

	ComponentEgressGateway = Component{
		Version:   "master",
		ImageName: "egress-gateway",
		Registry:  "",
	}

	ComponentL7Collector = Component{
		Version:   "master",
		ImageName: "l7-collector",
		Registry:  "",
	}

	ComponentEnvoyProxy = Component{
		Version:   "master",
		ImageName: "envoy",
		Registry:  "",
	}

	ComponentDikastes = Component{
		Version:   "master",
		ImageName: "dikastes",
		Registry:  "",
	}

	ComponentL7AdmissionController = Component{
		Version:   "master",
		ImageName: "l7-admission-controller",
		Registry:  "",
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.4.1",
	}

	ComponentPrometheus = Component{
		Version:   "master",
		ImageName: "prometheus",
		Registry:  "",
	}

	ComponentTigeraPrometheusService = Component{
		Version:   "master",
		ImageName: "prometheus-service",
		Registry:  "",
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.28.0",
	}

	ComponentPrometheusAlertmanager = Component{
		Version:   "master",
		ImageName: "alertmanager",
		Registry:  "",
	}

	ComponentQueryServer = Component{
		Version:   "master",
		ImageName: "queryserver",
		Registry:  "",
	}

	ComponentTigeraKubeControllers = Component{
		Version:   "master",
		ImageName: "kube-controllers",
		Registry:  "",
	}

	ComponentTigeraNode = Component{
		Version:   "master",
		ImageName: "node",
		Registry:  "",
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "master",
		ImageName: "node-windows",
		Registry:  "",
	}

	ComponentTigeraTypha = Component{
		Version:   "master",
		ImageName: "typha",
		Registry:  "",
	}

	ComponentTigeraCNI = Component{
		Version:   "master",
		ImageName: "cni",
		Registry:  "",
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "master",
		ImageName: "cni-windows",
		Registry:  "",
	}

	ComponentElasticsearchMetrics = Component{
		Version:   "master",
		ImageName: "elasticsearch-metrics",
		Registry:  "",
	}

	ComponentTigeraFlexVolume = Component{
		Version:   "master",
		ImageName: "pod2daemon-flexvol",
		Registry:  "",
	}

	ComponentTigeraCSI = Component{
		Version:   "master",
		ImageName: "csi",
		Registry:  "",
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:   "master",
		ImageName: "node-driver-registrar",
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "master",
		ImageName: "envoy-gateway",
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "master",
		ImageName: "envoy-proxy",
		Registry:  "",
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "master",
		ImageName: "envoy-ratelimit",
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
