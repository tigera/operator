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
	EnterpriseRelease string = "release-calient-v3.19"

	ComponentAPIServer = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cnx-apiserver",
		Registry: "",
	}

	ComponentComplianceBenchmarker = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/compliance-snapshotter",
		Registry: "",
	}

	ComponentCSRInitContainerPrivate = component{
		Version:  "master",
		Image:    "tigera/key-cert-provisioner",
		Registry: "",
	}

	ComponentDeepPacketInspection = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = component{
		Version:  "7.17.18",
		Registry: "",
	}

	ComponentEckKibana = component{
		Version:  "7.17.18",
		Registry: "",
	}

	ComponentElasticTseeInstaller = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentElasticsearchFIPS = component{
		Version:  "release-calient-v3.19-fips",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = component{
		Version:  "2.6.1",
		Registry: "",
	}

	ComponentElasticsearchOperator = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/eck-operator",
		Registry: "",
	}

	ComponentEsProxy = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/es-proxy",
		Registry: "",
	}

	ComponentESGateway = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/es-gateway",
		Registry: "",
	}

	ComponentLinseed = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/linseed",
		Registry: "",
	}

	ComponentFluentd = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/guardian",
		Registry: "",
	}

	ComponentIntrusionDetectionController = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/intrusion-detection-controller",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/webhooks-processor",
		Registry: "",
	}

	ComponentKibana = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/kibana",
		Registry: "",
	}

	ComponentManager = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cnx-manager",
		Registry: "",
	}

	ComponentDex = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/dex",
		Registry: "",
	}

	ComponentManagerProxy = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/voltron",
		Registry: "",
	}

	ComponentPacketCapture = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/envoy",
		Registry: "",
	}

	ComponentDikastes = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/dikastes",
		Registry: "",
	}

	ComponentCoreOSPrometheus = component{
		Version:  "v2.48.1",
		Registry: "",
	}

	ComponentPrometheus = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = component{
		Version:  "v0.25.0",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/alertmanager",
		Registry: "",
	}

	ComponentQueryServer = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cnx-queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/kube-controllers",
		Registry: "",
	}

	ComponentTigeraNode = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cnx-node",
		Registry: "",
	}

	ComponentTigeraNodeWindows = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cnx-node-windows",
		Registry: "",
	}

	ComponentTigeraTypha = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/typha",
		Registry: "",
	}

	ComponentTigeraCNI = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIFIPS = component{
		Version:  "release-calient-v3.19-fips",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIWindows = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cni-windows",
		Registry: "",
	}

	ComponentCloudControllers = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/cloud-controllers",
		Registry: "",
	}

	ComponentElasticsearchMetrics = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/elasticsearch-metrics",
		Registry: "",
	}

	ComponentFlexVolumePrivate = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCSIPrivate = component{
		Version:  "release-calient-v3.19",
		Image:    "tigera/csi",
		Registry: "",
	}

	ComponentCSINodeDriverRegistrarPrivate = component{
		Version:  "release-calient-v3.19",
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
		ComponentCSRInitContainerPrivate,
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
		ComponentCloudControllers,
		ComponentElasticsearchMetrics,
		ComponentESGateway,
		ComponentLinseed,
		ComponentDikastes,
		ComponentFlexVolumePrivate,
		ComponentCSIPrivate,
		ComponentCSINodeDriverRegistrarPrivate,
	}
)
