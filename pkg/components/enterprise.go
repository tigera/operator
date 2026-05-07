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
	EnterpriseRelease string = "test-build"

	ComponentTigeraCalico = Component{
		Version:   "test-build",
		Image:     "calico",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceBenchmarker = Component{
		Version:   "test-build",
		Image:     "compliance-benchmarker",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDeepPacketInspection = Component{
		Version:   "test-build",
		Image:     "deep-packet-inspection",
		Registry:  "",
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
		Version:   "test-build",
		Image:     "intrusion-detection-job-installer",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearch = Component{
		Version:   "test-build",
		Image:     "elasticsearch",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentECKElasticsearchOperator = Component{
		Version: "3.3.2",
		variant: enterpriseVariant,
	}

	ComponentElasticsearchOperator = Component{
		Version:   "test-build",
		Image:     "eck-operator",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentd = Component{
		Version:   "test-build",
		Image:     "fluentd",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentdWindows = Component{
		Version:   "test-build",
		Image:     "fluentd-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIntrusionDetectionController = Component{
		Version:   "test-build",
		Image:     "intrusion-detection-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentKibana = Component{
		Version:   "test-build",
		Image:     "kibana",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManager = Component{
		Version:   "test-build",
		Image:     "manager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDex = Component{
		Version:   "test-build",
		Image:     "dex",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEgressGateway = Component{
		Version:   "test-build",
		Image:     "egress-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayL7Collector = Component{
		Version:  "test-build",
		Image:    "gateway-l7-collector",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentEnvoyProxy = Component{
		Version:   "test-build",
		Image:     "envoy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDikastes = Component{
		Version:   "test-build",
		Image:     "dikastes",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.9.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheus = Component{
		Version:   "test-build",
		Image:     "prometheus",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.30.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheusAlertmanager = Component{
		Version:   "test-build",
		Image:     "alertmanager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNode = Component{
		Version:   "test-build",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "test-build",
		Image:     "node-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "test-build",
		Image:     "cni-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "test-build",
		Image:     "envoy-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "test-build",
		Image:     "envoy-proxy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "test-build",
		Image:     "envoy-ratelimit",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIstioPilot = Component{
		Version:  "test-build",
		Image:    "istio-pilot",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioInstallCNI = Component{
		Version:  "test-build",
		Image:    "istio-install-cni",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioZTunnel = Component{
		Version:  "test-build",
		Image:    "istio-ztunnel",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioProxyv2 = Component{
		Version:  "test-build",
		Image:    "istio-proxyv2",
		Registry: "",
		variant:  enterpriseVariant,
	}

	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	EnterpriseImages = []Component{
		ComponentTigeraCalico,
		ComponentComplianceBenchmarker,
		ComponentDeepPacketInspection,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentFluentd,
		ComponentFluentdWindows,
		ComponentIntrusionDetectionController,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentEgressGateway,
		ComponentGatewayL7Collector,
		ComponentEnvoyProxy,
		ComponentDikastes,
		ComponentPrometheus,
		ComponentPrometheusAlertmanager,
		ComponentTigeraNode,
		ComponentTigeraNodeWindows,
		ComponentTigeraCNIWindows,
		ComponentGatewayAPIEnvoyGateway,
		ComponentGatewayAPIEnvoyProxy,
		ComponentGatewayAPIEnvoyRatelimit,
		ComponentIstioPilot,
		ComponentIstioInstallCNI,
		ComponentIstioZTunnel,
		ComponentIstioProxyv2,
	}
)
