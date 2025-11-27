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
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceBenchmarker = Component{
		Version:   "master",
		Image:     "compliance-benchmarker",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceController = Component{
		Version:   "master",
		Image:     "compliance-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceReporter = Component{
		Version:   "master",
		Image:     "compliance-reporter",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceServer = Component{
		Version:   "master",
		Image:     "compliance-server",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceSnapshotter = Component{
		Version:   "master",
		Image:     "compliance-snapshotter",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:   "master",
		Image:     "key-cert-provisioner",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDeepPacketInspection = Component{
		Version:   "master",
		Image:     "deep-packet-inspection",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEckElasticsearch = Component{
		Version: "8.18.8",
		variant: enterpriseVariant,
	}

	ComponentEckKibana = Component{
		Version: "8.18.8",
		variant: enterpriseVariant,
	}

	ComponentElasticTseeInstaller = Component{
		Version:   "master",
		Image:     "intrusion-detection-job-installer",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearch = Component{
		Version:   "master",
		Image:     "elasticsearch",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentECKElasticsearchOperator = Component{
		Version: "2.16.0",
		variant: enterpriseVariant,
	}

	ComponentElasticsearchOperator = Component{
		Version:   "master",
		Image:     "eck-operator",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentUIAPIs = Component{
		Version:   "master",
		Image:     "ui-apis",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentESGateway = Component{
		Version:   "master",
		Image:     "es-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentLinseed = Component{
		Version:   "master",
		Image:     "linseed",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentd = Component{
		Version:   "master",
		Image:     "fluentd",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentdWindows = Component{
		Version:   "master",
		Image:     "fluentd-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGuardian = Component{
		Version:   "master",
		Image:     "guardian",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIntrusionDetectionController = Component{
		Version:   "master",
		Image:     "intrusion-detection-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentWAFHTTPFilter = Component{
		Version:   "master",
		Image:     "waf-http-filter",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:   "master",
		Image:     "webhooks-processor",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentKibana = Component{
		Version:   "master",
		Image:     "kibana",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManager = Component{
		Version:   "master",
		Image:     "manager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDex = Component{
		Version:   "master",
		Image:     "dex",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManagerProxy = Component{
		Version:   "master",
		Image:     "voltron",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentPacketCapture = Component{
		Version:   "master",
		Image:     "packetcapture",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentPolicyRecommendation = Component{
		Version:   "master",
		Image:     "policy-recommendation",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEgressGateway = Component{
		Version:   "master",
		Image:     "egress-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentL7Collector = Component{
		Version:   "master",
		Image:     "l7-collector",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayL7Collector = Component{
		Version:  "master",
		Image:    "gateway-l7-collector",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentEnvoyProxy = Component{
		Version:   "master",
		Image:     "envoy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDikastes = Component{
		Version:   "master",
		Image:     "dikastes",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentL7AdmissionController = Component{
		Version:   "master",
		Image:     "l7-admission-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.4.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheus = Component{
		Version:   "master",
		Image:     "prometheus",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraPrometheusService = Component{
		Version:   "master",
		Image:     "prometheus-service",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.28.0",
		variant: enterpriseVariant,
	}

	ComponentPrometheusAlertmanager = Component{
		Version:   "master",
		Image:     "alertmanager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentQueryServer = Component{
		Version:   "master",
		Image:     "queryserver",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraKubeControllers = Component{
		Version:   "master",
		Image:     "kube-controllers",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNode = Component{
		Version:   "master",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "master",
		Image:     "node-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraTypha = Component{
		Version:   "master",
		Image:     "typha",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNI = Component{
		Version:   "master",
		Image:     "cni",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "master",
		Image:     "cni-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearchMetrics = Component{
		Version:   "master",
		Image:     "elasticsearch-metrics",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraFlexVolume = Component{
		Version:   "master",
		Image:     "pod2daemon-flexvol",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSI = Component{
		Version:   "master",
		Image:     "csi",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:   "master",
		Image:     "node-driver-registrar",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "master",
		Image:     "envoy-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "master",
		Image:     "envoy-proxy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "master",
		Image:     "envoy-ratelimit",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCalicoIstioPilot = Component{
		Version:  "master",
		Image:    "istio-pilot",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentCalicoIstioInstallCNI = Component{
		Version:  "master",
		Image:    "istio-install-cni",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentCalicoIstioZTunnel = Component{
		Version:  "master",
		Image:    "istio-ztunnel",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentCalicoIstioProxyv2 = Component{
		Version:  "master",
		Image:    "istio-proxyv2",
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
		ComponentCalicoIstioPilot,
		ComponentCalicoIstioInstallCNI,
		ComponentCalicoIstioZTunnel,
		ComponentCalicoIstioProxyv2,
	}
)
