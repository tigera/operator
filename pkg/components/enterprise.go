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
	EnterpriseRelease string = "v3.20.1"

	ComponentAPIServer = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/cnx-apiserver",
		Registry: "",
	}

	ComponentComplianceBenchmarker = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/compliance-snapshotter",
		Registry: "",
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/key-cert-provisioner",
		Registry: "",
	}

	ComponentDeepPacketInspection = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = Component{
		Version:  "7.17.25",
		Registry: "",
	}

	ComponentEckKibana = Component{
		Version:  "7.17.25",
		Registry: "",
	}

	ComponentElasticTseeInstaller = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentElasticsearchFIPS = Component{
		Version:  "v3.20.0-2.2-fips",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = Component{
		Version:  "2.16.0",
		Registry: "",
	}

	ComponentElasticsearchOperator = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/eck-operator",
		Registry: "",
	}

	ComponentEsProxy = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/es-proxy",
		Registry: "",
	}

	ComponentESGateway = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/es-gateway",
		Registry: "",
	}

	ComponentLinseed = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/linseed",
		Registry: "",
	}

	ComponentFluentd = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/guardian",
		Registry: "",
	}

	ComponentIntrusionDetectionController = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/intrusion-detection-controller",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/webhooks-processor",
		Registry: "",
	}

	ComponentKibana = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/kibana",
		Registry: "",
	}

	ComponentManager = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/cnx-manager",
		Registry: "",
	}

	ComponentDex = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/dex",
		Registry: "",
	}

	ComponentManagerProxy = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/voltron",
		Registry: "",
	}

	ComponentPacketCapture = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/envoy",
		Registry: "",
	}

	ComponentDikastes = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/dikastes",
		Registry: "",
	}

	ComponentL7AdmissionController = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/l7-admission-controller",
		Registry: "",
	}

	ComponentCoreOSPrometheus = Component{
		Version:  "v2.54.1",
		Registry: "",
	}

	ComponentPrometheus = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = Component{
		Version:  "v0.27.0",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/alertmanager",
		Registry: "",
	}

	ComponentQueryServer = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/cnx-queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/kube-controllers",
		Registry: "",
	}

	ComponentTigeraNode = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/cnx-node",
		Registry: "",
	}

	ComponentTigeraNodeWindows = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/cnx-node-windows",
		Registry: "",
	}

	ComponentTigeraTypha = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/typha",
		Registry: "",
	}

	ComponentTigeraCNI = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIFIPS = Component{
		Version:  "v3.20.0-2.2-fips",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIWindows = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/cni-windows",
		Registry: "",
	}

	ComponentElasticsearchMetrics = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/elasticsearch-metrics",
		Registry: "",
	}

	ComponentTigeraFlexVolume = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentTigeraCSI = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/csi",
		Registry: "",
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:  "v3.20.0-2.2",
		Image:    "tigera/node-driver-registrar",
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
		ComponentElasticsearchFIPS,
		ComponentElasticsearchOperator,
		ComponentEsProxy,
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
		ComponentTigeraCNIFIPS,
		ComponentTigeraCNIWindows,
		ComponentElasticsearchMetrics,
		ComponentESGateway,
		ComponentLinseed,
		ComponentDikastes,
		ComponentL7AdmissionController,
		ComponentTigeraFlexVolume,
		ComponentTigeraCSI,
		ComponentTigeraCSINodeDriverRegistrar,
	}
)
