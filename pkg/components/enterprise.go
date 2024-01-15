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
	EnterpriseRelease string = "master"

	ComponentAPIServer = component{
		Version:  "master",
		Image:    "tigera/cnx-apiserver",
		Registry: "",
	}

	ComponentComplianceBenchmarker = component{
		Version:  "master",
		Image:    "tigera/compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = component{
		Version:  "master",
		Image:    "tigera/compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = component{
		Version:  "master",
		Image:    "tigera/compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = component{
		Version:  "master",
		Image:    "tigera/compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = component{
		Version:  "master",
		Image:    "tigera/compliance-snapshotter",
		Registry: "",
	}

	ComponentDeepPacketInspection = component{
		Version:  "master",
		Image:    "tigera/deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = component{
		Version:  "7.17.16",
		Registry: "",
	}

	ComponentEckKibana = component{
		Version:  "7.17.16",
		Registry: "",
	}

	ComponentElasticTseeInstaller = component{
		Version:  "master",
		Image:    "tigera/intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = component{
		Version:  "master",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentElasticsearchFIPS = component{
		Version:  "master-fips",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = component{
		Version:  "2.6.1",
		Registry: "",
	}

	ComponentElasticsearchOperator = component{
		Version:  "master",
		Image:    "tigera/eck-operator",
		Registry: "",
	}

	ComponentEsProxy = component{
		Version:  "master",
		Image:    "tigera/es-proxy",
		Registry: "",
	}

	ComponentESGateway = component{
		Version:  "master",
		Image:    "tigera/es-gateway",
		Registry: "",
	}

	ComponentLinseed = component{
		Version:  "master",
		Image:    "tigera/linseed",
		Registry: "",
	}

	ComponentFluentd = component{
		Version:  "master",
		Image:    "tigera/fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = component{
		Version:  "master",
		Image:    "tigera/fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = component{
		Version:  "master",
		Image:    "tigera/guardian",
		Registry: "",
	}

	ComponentIntrusionDetectionController = component{
		Version:  "master",
		Image:    "tigera/intrusion-detection-controller",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = component{
		Version:  "master",
		Image:    "tigera/webhooks-processor",
		Registry: "",
	}

	ComponentKibana = component{
		Version:  "master",
		Image:    "tigera/kibana",
		Registry: "",
	}

	ComponentManager = component{
		Version:  "master",
		Image:    "tigera/cnx-manager",
		Registry: "",
	}

	ComponentDex = component{
		Version:  "master",
		Image:    "tigera/dex",
		Registry: "",
	}

	ComponentManagerProxy = component{
		Version:  "master",
		Image:    "tigera/voltron",
		Registry: "",
	}

	ComponentPacketCapture = component{
		Version:  "master",
		Image:    "tigera/packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = component{
		Version:  "master",
		Image:    "tigera/policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = component{
		Version:  "master",
		Image:    "tigera/egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = component{
		Version:  "master",
		Image:    "tigera/l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = component{
		Version:  "master",
		Image:    "tigera/envoy",
		Registry: "",
	}

	ComponentDikastes = component{
		Version:  "master",
		Image:    "tigera/dikastes",
		Registry: "",
	}

	ComponentCoreOSPrometheus = component{
		Version:  "v2.48.1",
		Registry: "",
	}

	ComponentPrometheus = component{
		Version:  "master",
		Image:    "tigera/prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = component{
		Version:  "master",
		Image:    "tigera/prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = component{
		Version:  "v0.25.0",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = component{
		Version:  "master",
		Image:    "tigera/alertmanager",
		Registry: "",
	}

	ComponentQueryServer = component{
		Version:  "master",
		Image:    "tigera/cnx-queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = component{
		Version:  "master",
		Image:    "tigera/kube-controllers",
		Registry: "",
	}

	ComponentTigeraNode = component{
		Version:  "master",
		Image:    "tigera/cnx-node",
		Registry: "",
	}

	ComponentTigeraNodeWindows = component{
		Version:  "master",
		Image:    "tigera/cnx-node-windows",
		Registry: "",
	}

	ComponentTigeraTypha = component{
		Version:  "master",
		Image:    "tigera/typha",
		Registry: "",
	}

	ComponentTigeraCNI = component{
		Version:  "master",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIFIPS = component{
		Version:  "master-fips",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIWindows = component{
		Version:  "master",
		Image:    "tigera/cni-windows",
		Registry: "",
	}

	ComponentCloudControllers = component{
		Version:  "master",
		Image:    "tigera/cloud-controllers",
		Registry: "",
	}

	ComponentElasticsearchMetrics = component{
		Version:  "master",
		Image:    "tigera/elasticsearch-metrics",
		Registry: "",
	}

	ComponentFlexVolumePrivate = component{
		Version:  "master",
		Image:    "tigera/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCSIPrivate = component{
		Version:  "master",
		Image:    "tigera/csi",
		Registry: "",
	}

	ComponentCSINodeDriverRegistrarPrivate = component{
		Version:  "master",
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
		ComponentTigeraTypha,
		ComponentTigeraCNI,
		ComponentTigeraCNIFIPS,
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
