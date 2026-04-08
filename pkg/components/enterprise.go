// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "apiserver",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceBenchmarker = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "compliance-benchmarker",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceController = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "compliance-controller",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceReporter = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "compliance-reporter",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceServer = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "compliance-server",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceSnapshotter = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "compliance-snapshotter",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "key-cert-provisioner",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDeepPacketInspection = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "deep-packet-inspection",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEckElasticsearch = Component{
		Version: "8.19.12",
		variant: enterpriseVariant,
	}

	ComponentEckKibana = Component{
		Version: "8.19.12",
		variant: enterpriseVariant,
	}

	ComponentElasticTseeInstaller = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "intrusion-detection-job-installer",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearch = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "elasticsearch",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentECKElasticsearchOperator = Component{
		Version: "3.3.0",
		variant: enterpriseVariant,
	}

	ComponentElasticsearchOperator = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "eck-operator",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentUIAPIs = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "ui-apis",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentESGateway = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "es-gateway",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentLinseed = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "linseed",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentd = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "fluentd",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentdWindows = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "fluentd-windows",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGuardian = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "guardian",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIntrusionDetectionController = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "intrusion-detection-controller",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentWAFHTTPFilter = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "waf-http-filter",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "webhooks-processor",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentKibana = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "kibana",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManager = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-32-g022295c17185",
		Image:     "manager",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDex = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "dex",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManagerProxy = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "voltron",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentPacketCapture = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "packetcapture",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentPolicyRecommendation = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "policy-recommendation",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEgressGateway = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "egress-gateway",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentL7Collector = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "l7-collector",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayL7Collector = Component{
		Version:  "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:    "gateway-l7-collector",
		Registry: "gcr.io/unique-caldron-775/cnx/",
		variant:  enterpriseVariant,
	}

	ComponentEnvoyProxy = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "envoy",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDikastes = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "dikastes",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentL7AdmissionController = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "l7-admission-controller",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.9.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheus = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "prometheus",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraPrometheusService = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "prometheus-service",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.31.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheusAlertmanager = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "alertmanager",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentQueryServer = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "queryserver",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraKubeControllers = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "kube-controllers",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNode = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "node",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "node-windows",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraTypha = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "typha",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNI = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "cni",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "cni-windows",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearchMetrics = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "elasticsearch-metrics",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraFlexVolume = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "pod2daemon-flexvol",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSI = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "csi",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "node-driver-registrar",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "envoy-gateway",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "envoy-proxy",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "envoy-ratelimit",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIstioPilot = Component{
		Version:  "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:    "istio-pilot",
		Registry: "gcr.io/unique-caldron-775/cnx/",
		variant:  enterpriseVariant,
	}

	ComponentIstioInstallCNI = Component{
		Version:  "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:    "istio-install-cni",
		Registry: "gcr.io/unique-caldron-775/cnx/",
		variant:  enterpriseVariant,
	}

	ComponentIstioZTunnel = Component{
		Version:  "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:    "istio-ztunnel",
		Registry: "gcr.io/unique-caldron-775/cnx/",
		variant:  enterpriseVariant,
	}

	ComponentIstioProxyv2 = Component{
		Version:  "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:    "istio-proxyv2",
		Registry: "gcr.io/unique-caldron-775/cnx/",
		variant:  enterpriseVariant,
	}

	ComponentTigeraWebhooks = Component{
		Version:   "v3.24.0-1.0-calient-0.dev-724-g4e8956a44a22",
		Image:     "webhooks",
		Registry:  "gcr.io/unique-caldron-775/cnx/",
		imagePath: "",
		variant:   enterpriseVariant,
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
		ComponentIstioPilot,
		ComponentIstioInstallCNI,
		ComponentIstioZTunnel,
		ComponentIstioProxyv2,
		ComponentTigeraWebhooks,
	}
)
