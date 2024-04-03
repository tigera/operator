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
	EnterpriseRelease string = "{{ .Title }}"
{{ with index .Components "cnx-apiserver" }}
	ComponentAPIServer = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-benchmarker" }}
	ComponentComplianceBenchmarker = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-controller" }}
	ComponentComplianceController = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-reporter" }}
	ComponentComplianceReporter = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-server" }}
	ComponentComplianceServer = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-snapshotter" }}
	ComponentComplianceSnapshotter = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "key-cert-provisioner" }}
	ComponentTigeraCSRInitContainer = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "deep-packet-inspection" }}
	ComponentDeepPacketInspection = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "eck-elasticsearch" }}
	ComponentEckElasticsearch = component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "eck-kibana" }}
	ComponentEckKibana = component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "elastic-tsee-installer" }}
	ComponentElasticTseeInstaller = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.elasticsearch }}
	ComponentElasticsearch = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.elasticsearch }}
	ComponentElasticsearchFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "eck-elasticsearch-operator" }}
	ComponentECKElasticsearchOperator = component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "elasticsearch-operator" }}
	ComponentElasticsearchOperator = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "es-proxy" }}
	ComponentEsProxy = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "es-gateway" }}
	ComponentESGateway = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "linseed" }}
	ComponentLinseed = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.fluentd }}
	ComponentFluentd = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "fluentd-windows" }}
	ComponentFluentdWindows = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.guardian }}
	ComponentGuardian = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "intrusion-detection-controller" }}
	ComponentIntrusionDetectionController = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "security-event-webhooks-processor" }}
	ComponentSecurityEventWebhooksProcessor = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.kibana }}
	ComponentKibana = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-manager" }}
	ComponentManager = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "dex" }}
	ComponentDex = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.voltron }}
	ComponentManagerProxy = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "packetcapture" }}
	ComponentPacketCapture = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "policy-recommendation" }}
	ComponentPolicyRecommendation = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "egress-gateway" }}
	ComponentEgressGateway = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "l7-collector" }}
	ComponentL7Collector = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "envoy" }}
	ComponentEnvoyProxy = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "dikastes" }}
	ComponentDikastes = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "coreos-prometheus" }}
	ComponentCoreOSPrometheus = component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "prometheus" }}
	ComponentPrometheus = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-prometheus-service" }}
	ComponentTigeraPrometheusService = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "coreos-alertmanager" }}
	ComponentCoreOSAlertmanager = component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "alertmanager" }}
	ComponentPrometheusAlertmanager = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-queryserver" }}
	ComponentQueryServer = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-kube-controllers" }}
	ComponentTigeraKubeControllers = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-node" }}
	ComponentTigeraNode = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-node-windows" }}
	ComponentTigeraNodeWindows = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.typha }}
	ComponentTigeraTypha = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-cni" }}
	ComponentTigeraCNI = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-cni" }}
	ComponentTigeraCNIFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-cni-windows" }}
	ComponentTigeraCNIWindows = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "elasticsearch-metrics" }}
	ComponentElasticsearchMetrics = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "flexvol" }}
	ComponentTigeraFlexVolume = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "csi" }}
	ComponentTigeraCSI = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "csi-node-driver-registrar" }}
	ComponentTigeraCSINodeDriverRegistrar = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
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
