// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	EnterpriseRelease string = "release-calient-v3.21-1"

	ComponentAPIServer = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/cnx-apiserver",
		Registry: "",
	}

	ComponentComplianceBenchmarker = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/compliance-snapshotter",
		Registry: "",
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/key-cert-provisioner",
		Registry: "",
	}

	ComponentDeepPacketInspection = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = Component{
		Version:  "8.16.1",
		Registry: "",
	}

	ComponentEckKibana = Component{
		Version:  "8.16.1",
		Registry: "",
	}

	ComponentElasticTseeInstaller = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = Component{
		Version:  "2.6.1",
		Registry: "",
	}

	ComponentElasticsearchOperator = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/eck-operator",
		Registry: "",
	}

	ComponentUIAPIs = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/ui-apis",
		Registry: "",
	}

	ComponentESGateway = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/es-gateway",
		Registry: "",
	}

	ComponentLinseed = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/linseed",
		Registry: "",
	}

	ComponentFluentd = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/guardian",
		Registry: "",
	}

	ComponentIntrusionDetectionController = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/intrusion-detection-controller",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/webhooks-processor",
		Registry: "",
	}

	ComponentKibana = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/kibana",
		Registry: "",
	}

	ComponentManager = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/cnx-manager",
		Registry: "",
	}

	ComponentDex = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/dex",
		Registry: "",
	}

	ComponentManagerProxy = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/voltron",
		Registry: "",
	}

	ComponentPacketCapture = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/envoy",
		Registry: "",
	}

	ComponentDikastes = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/dikastes",
		Registry: "",
	}

	ComponentL7AdmissionController = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/l7-admission-controller",
		Registry: "",
	}

	ComponentCoreOSPrometheus = Component{
		Version:  "v2.54.1",
		Registry: "",
	}

	ComponentPrometheus = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = Component{
		Version:  "v0.27.0",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/alertmanager",
		Registry: "",
	}

	ComponentQueryServer = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/cnx-queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/kube-controllers",
		Registry: "",
	}

	ComponentTigeraNode = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/cnx-node",
		Registry: "",
	}

	ComponentTigeraNodeWindows = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/cnx-node-windows",
		Registry: "",
	}

	ComponentTigeraTypha = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/typha",
		Registry: "",
	}

	ComponentTigeraCNI = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIWindows = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/cni-windows",
		Registry: "",
	}

	ComponentElasticsearchMetrics = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/elasticsearch-metrics",
		Registry: "",
	}

	ComponentTigeraFlexVolume = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentTigeraCSI = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/csi",
		Registry: "",
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:  "release-calient-v3.21-1",
		Image:    "tigera/node-driver-registrar",
		Registry: "",
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:  "v1.1.2",
		Image:    "envoyproxy/gateway",
		Registry: "docker.io/",
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:  "distroless-v1.31.0",
		Image:    "envoyproxy/envoy",
		Registry: "docker.io/",
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:  "26f28d78",
		Image:    "envoyproxy/ratelimit",
		Registry: "docker.io/",
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
