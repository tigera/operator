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
	EnterpriseRelease string = "v3.19.4"

	ComponentAPIServer = component{
		Version:  "v3.19.4",
		Image:    "tigera/cnx-apiserver",
		Registry: "",
	}

	ComponentComplianceBenchmarker = component{
		Version:  "v3.19.4",
		Image:    "tigera/compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = component{
		Version:  "v3.19.4",
		Image:    "tigera/compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = component{
		Version:  "v3.19.4",
		Image:    "tigera/compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = component{
		Version:  "v3.19.4",
		Image:    "tigera/compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = component{
		Version:  "v3.19.4",
		Image:    "tigera/compliance-snapshotter",
		Registry: "",
	}

	ComponentTigeraCSRInitContainer = component{
		Version:  "v3.19.4",
		Image:    "tigera/key-cert-provisioner",
		Registry: "",
	}

	ComponentDeepPacketInspection = component{
		Version:  "v3.19.4",
		Image:    "tigera/deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = component{
		Version:  "7.17.25",
		Registry: "",
	}

	ComponentEckKibana = component{
		Version:  "7.17.25",
		Registry: "",
	}

	ComponentElasticTseeInstaller = component{
		Version:  "v3.19.4",
		Image:    "tigera/intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = component{
		Version:  "v3.19.4",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentElasticsearchFIPS = component{
		Version:  "v3.19.4-fips",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = component{
		Version:  "2.6.1",
		Registry: "",
	}

	ComponentElasticsearchOperator = component{
		Version:  "v3.19.4",
		Image:    "tigera/eck-operator",
		Registry: "",
	}

	ComponentEsProxy = component{
		Version:  "v3.19.4",
		Image:    "tigera/es-proxy",
		Registry: "",
	}

	ComponentESGateway = component{
		Version:  "v3.19.4",
		Image:    "tigera/es-gateway",
		Registry: "",
	}

	ComponentLinseed = component{
		Version:  "v3.19.4",
		Image:    "tigera/linseed",
		Registry: "",
	}

	ComponentFluentd = component{
		Version:  "v3.19.4",
		Image:    "tigera/fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = component{
		Version:  "v3.19.4",
		Image:    "tigera/fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = component{
		Version:  "v3.19.4",
		Image:    "tigera/guardian",
		Registry: "",
	}

	ComponentIntrusionDetectionController = component{
		Version:  "v3.19.4",
		Image:    "tigera/intrusion-detection-controller",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = component{
		Version:  "v3.19.4",
		Image:    "tigera/webhooks-processor",
		Registry: "",
	}

	ComponentKibana = component{
		Version:  "v3.19.4",
		Image:    "tigera/kibana",
		Registry: "",
	}

	ComponentManager = component{
		Version:  "v3.19.4",
		Image:    "tigera/cnx-manager",
		Registry: "",
	}

	ComponentDex = component{
		Version:  "v3.19.4",
		Image:    "tigera/dex",
		Registry: "",
	}

	ComponentManagerProxy = component{
		Version:  "v3.19.4",
		Image:    "tigera/voltron",
		Registry: "",
	}

	ComponentPacketCapture = component{
		Version:  "v3.19.4",
		Image:    "tigera/packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = component{
		Version:  "v3.19.4",
		Image:    "tigera/policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = component{
		Version:  "v3.19.4",
		Image:    "tigera/egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = component{
		Version:  "v3.19.4",
		Image:    "tigera/l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = component{
		Version:  "v3.19.4",
		Image:    "tigera/envoy",
		Registry: "",
	}

	ComponentDikastes = component{
		Version:  "v3.19.4",
		Image:    "tigera/dikastes",
		Registry: "",
	}

	ComponentCoreOSPrometheus = component{
		Version:  "v2.54.1",
		Registry: "",
	}

	ComponentPrometheus = component{
		Version:  "v3.19.4",
		Image:    "tigera/prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = component{
		Version:  "v3.19.4",
		Image:    "tigera/prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = component{
		Version:  "v0.27.0",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = component{
		Version:  "v3.19.4",
		Image:    "tigera/alertmanager",
		Registry: "",
	}

	ComponentQueryServer = component{
		Version:  "v3.19.4",
		Image:    "tigera/cnx-queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = component{
		Version:  "v3.19.4",
		Image:    "tigera/kube-controllers",
		Registry: "",
	}

	ComponentTigeraNode = component{
		Version:  "v3.19.4",
		Image:    "tigera/cnx-node",
		Registry: "",
	}

	ComponentTigeraNodeWindows = component{
		Version:  "v3.19.4",
		Image:    "tigera/cnx-node-windows",
		Registry: "",
	}

	ComponentTigeraTypha = component{
		Version:  "v3.19.4",
		Image:    "tigera/typha",
		Registry: "",
	}

	ComponentTigeraCNI = component{
		Version:  "v3.19.4",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIFIPS = component{
		Version:  "v3.19.4-fips",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIWindows = component{
		Version:  "v3.19.4",
		Image:    "tigera/cni-windows",
		Registry: "",
	}

	ComponentElasticsearchMetrics = component{
		Version:  "v3.19.4",
		Image:    "tigera/elasticsearch-metrics",
		Registry: "",
	}

	ComponentTigeraFlexVolume = component{
		Version:  "v3.19.4",
		Image:    "tigera/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentTigeraCSI = component{
		Version:  "v3.19.4",
		Image:    "tigera/csi",
		Registry: "",
	}

	ComponentTigeraCSINodeDriverRegistrar = component{
		Version:  "v3.19.4",
		Image:    "tigera/node-driver-registrar",
		Registry: "",
	}
	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	EnterpriseImages = []component{
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
		ComponentTigeraFlexVolume,
		ComponentTigeraCSI,
		ComponentTigeraCSINodeDriverRegistrar,
	}
)
