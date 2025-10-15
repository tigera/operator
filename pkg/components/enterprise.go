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
		Version:  "master",
		Image:    "apiserver",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentComplianceBenchmarker = Component{
		Version:  "master",
		Image:    "compliance-benchmarker",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentComplianceController = Component{
		Version:  "master",
		Image:    "compliance-controller",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentComplianceReporter = Component{
		Version:  "master",
		Image:    "compliance-reporter",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentComplianceServer = Component{
		Version:  "master",
		Image:    "compliance-server",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentComplianceSnapshotter = Component{
		Version:  "master",
		Image:    "compliance-snapshotter",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:  "master",
		Image:    "key-cert-provisioner",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentDeepPacketInspection = Component{
		Version:  "master",
		Image:    "deep-packet-inspection",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentEckElasticsearch = Component{
		Version: "8.18.4",
		variant: enterpriseVariant,
	}

	ComponentEckKibana = Component{
		Version: "8.18.4",
		variant: enterpriseVariant,
	}

	ComponentElasticTseeInstaller = Component{
		Version:  "master",
		Image:    "intrusion-detection-job-installer",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentElasticsearch = Component{
		Version:  "master",
		Image:    "elasticsearch",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentECKElasticsearchOperator = Component{
		Version: "2.16.0",
		variant: enterpriseVariant,
	}

	ComponentElasticsearchOperator = Component{
		Version:  "master",
		Image:    "eck-operator",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentUIAPIs = Component{
		Version:  "master",
		Image:    "ui-apis",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentESGateway = Component{
		Version:  "master",
		Image:    "es-gateway",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentLinseed = Component{
		Version:  "master",
		Image:    "linseed",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentFluentd = Component{
		Version:  "master",
		Image:    "fluentd",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentFluentdWindows = Component{
		Version:  "master",
		Image:    "fluentd-windows",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentGuardian = Component{
		Version:  "master",
		Image:    "guardian",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIntrusionDetectionController = Component{
		Version:  "master",
		Image:    "intrusion-detection-controller",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentWAFHTTPFilter = Component{
		Version:  "master",
		Image:    "waf-http-filter",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:  "master",
		Image:    "webhooks-processor",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentKibana = Component{
		Version:  "master",
		Image:    "kibana",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentManager = Component{
		Version:  "master",
		Image:    "manager",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentDex = Component{
		Version:  "master",
		Image:    "dex",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentManagerProxy = Component{
		Version:  "master",
		Image:    "voltron",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentPacketCapture = Component{
		Version:  "master",
		Image:    "packetcapture",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentPolicyRecommendation = Component{
		Version:  "master",
		Image:    "policy-recommendation",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentEgressGateway = Component{
		Version:  "master",
		Image:    "egress-gateway",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentL7Collector = Component{
		Version:  "master",
		Image:    "l7-collector",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentGatewayL7Collector = Component{
		Version:  "master",
		Image:    "tigera/gateway-l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = Component{
		Version:  "master",
		Image:    "envoy",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentDikastes = Component{
		Version:  "master",
		Image:    "dikastes",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentL7AdmissionController = Component{
		Version:  "master",
		Image:    "l7-admission-controller",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.4.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheus = Component{
		Version:  "master",
		Image:    "prometheus",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraPrometheusService = Component{
		Version:  "master",
		Image:    "prometheus-service",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.28.0",
		variant: enterpriseVariant,
	}

	ComponentPrometheusAlertmanager = Component{
		Version:  "master",
		Image:    "alertmanager",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentQueryServer = Component{
		Version:  "master",
		Image:    "queryserver",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraKubeControllers = Component{
		Version:  "master",
		Image:    "kube-controllers",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraNode = Component{
		Version:  "master",
		Image:    "node",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraNodeWindows = Component{
		Version:  "master",
		Image:    "node-windows",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraTypha = Component{
		Version:  "master",
		Image:    "typha",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraCNI = Component{
		Version:  "master",
		Image:    "cni",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraCNIWindows = Component{
		Version:  "master",
		Image:    "cni-windows",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentElasticsearchMetrics = Component{
		Version:  "master",
		Image:    "elasticsearch-metrics",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraFlexVolume = Component{
		Version:  "master",
		Image:    "pod2daemon-flexvol",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraCSI = Component{
		Version:  "master",
		Image:    "csi",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:  "master",
		Image:    "node-driver-registrar",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:  "master",
		Image:    "envoy-gateway",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:  "master",
		Image:    "envoy-proxy",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:  "master",
		Image:    "envoy-ratelimit",
		Registry: "",
		variant:  enterpriseVariant,
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
		ComponentGatewayL7Collector,
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
