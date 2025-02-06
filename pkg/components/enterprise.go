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
		Image:    "tigera/cnx-apiserver",
		Registry: "",
	}

	ComponentComplianceBenchmarker = Component{
		Version:  "master",
		Image:    "tigera/compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = Component{
		Version:  "master",
		Image:    "tigera/compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = Component{
		Version:  "master",
		Image:    "tigera/compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = Component{
		Version:  "master",
		Image:    "tigera/compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = Component{
		Version:  "master",
		Image:    "tigera/compliance-snapshotter",
		Registry: "",
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:  "master",
		Image:    "tigera/key-cert-provisioner",
		Registry: "",
	}

	ComponentDeepPacketInspection = Component{
		Version:  "master",
		Image:    "tigera/deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = Component{
		Version:  "8.17.1",
		Registry: "",
	}

	ComponentEckKibana = Component{
		Version:  "8.17.1",
		Registry: "",
	}

	ComponentElasticTseeInstaller = Component{
		Version:  "master",
		Image:    "tigera/intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = Component{
		Version:  "master",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = Component{
		Version:  "2.16.0",
		Registry: "",
	}

	ComponentElasticsearchOperator = Component{
		Version:  "master",
		Image:    "tigera/eck-operator",
		Registry: "",
	}

	ComponentUIAPIs = Component{
		Version:  "master",
		Image:    "tigera/ui-apis",
		Registry: "",
	}

	ComponentESGateway = Component{
		Version:  "master",
		Image:    "tigera/es-gateway",
		Registry: "",
	}

	ComponentLinseed = Component{
		Version:  "master",
		Image:    "tigera/linseed",
		Registry: "",
	}

	ComponentFluentd = Component{
		Version:  "master",
		Image:    "tigera/fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = Component{
		Version:  "master",
		Image:    "tigera/fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = Component{
		Version:  "master",
		Image:    "tigera/guardian",
		Registry: "",
	}

	ComponentIntrusionDetectionController = Component{
		Version:  "master",
		Image:    "tigera/intrusion-detection-controller",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:  "master",
		Image:    "tigera/webhooks-processor",
		Registry: "",
	}

	ComponentKibana = Component{
		Version:  "master",
		Image:    "tigera/kibana",
		Registry: "",
	}

	ComponentManager = Component{
		Version:  "master",
		Image:    "tigera/cnx-manager",
		Registry: "",
	}

	ComponentDex = Component{
		Version:  "master",
		Image:    "tigera/dex",
		Registry: "",
	}

	ComponentManagerProxy = Component{
		Version:  "master",
		Image:    "tigera/voltron",
		Registry: "",
	}

	ComponentPacketCapture = Component{
		Version:  "master",
		Image:    "tigera/packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = Component{
		Version:  "master",
		Image:    "tigera/policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = Component{
		Version:  "master",
		Image:    "tigera/egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = Component{
		Version:  "master",
		Image:    "tigera/l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = Component{
		Version:  "master",
		Image:    "tigera/envoy",
		Registry: "",
	}

	ComponentDikastes = Component{
		Version:  "master",
		Image:    "tigera/dikastes",
		Registry: "",
	}

	ComponentL7AdmissionController = Component{
		Version:  "master",
		Image:    "tigera/l7-admission-controller",
		Registry: "",
	}

	ComponentCoreOSPrometheus = Component{
		Version:  "v2.54.1",
		Registry: "",
	}

	ComponentPrometheus = Component{
		Version:  "master",
		Image:    "tigera/prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = Component{
		Version:  "master",
		Image:    "tigera/prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = Component{
		Version:  "v0.28.0",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = Component{
		Version:  "master",
		Image:    "tigera/alertmanager",
		Registry: "",
	}

	ComponentQueryServer = Component{
		Version:  "master",
		Image:    "tigera/cnx-queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = Component{
		Version:  "master",
		Image:    "tigera/kube-controllers",
		Registry: "",
	}

	ComponentTigeraNode = Component{
		Version:  "master",
		Image:    "tigera/cnx-node",
		Registry: "",
	}

	ComponentTigeraNodeWindows = Component{
		Version:  "master",
		Image:    "tigera/cnx-node-windows",
		Registry: "",
	}

	ComponentTigeraTypha = Component{
		Version:  "master",
		Image:    "tigera/typha",
		Registry: "",
	}

	ComponentTigeraCNI = Component{
		Version:  "master",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIWindows = Component{
		Version:  "master",
		Image:    "tigera/cni-windows",
		Registry: "",
	}

	ComponentElasticsearchMetrics = Component{
		Version:  "master",
		Image:    "tigera/elasticsearch-metrics",
		Registry: "",
	}

	ComponentTigeraFlexVolume = Component{
		Version:  "master",
		Image:    "tigera/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentTigeraCSI = Component{
		Version:  "master",
		Image:    "tigera/csi",
		Registry: "",
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:  "master",
		Image:    "tigera/node-driver-registrar",
		Registry: "",
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:  "master",
		Image:    "tigera/envoy-gateway",
		Registry: "",
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:  "master",
		Image:    "tigera/envoy-proxy",
		Registry: "",
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:  "master",
		Image:    "tigera/envoy-ratelimit",
		Registry: "",
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
