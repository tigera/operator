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
	ComponentAPIServer = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-benchmarker" }}
	ComponentComplianceBenchmarker = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-controller" }}
	ComponentComplianceController = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-reporter" }}
	ComponentComplianceReporter = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-server" }}
	ComponentComplianceServer = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "compliance-snapshotter" }}
	ComponentComplianceSnapshotter = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "key-cert-provisioner" }}
	ComponentTigeraCSRInitContainer = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "deep-packet-inspection" }}
	ComponentDeepPacketInspection = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "eck-elasticsearch" }}
	ComponentEckElasticsearch = Component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "eck-kibana" }}
	ComponentEckKibana = Component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "elastic-tsee-installer" }}
	ComponentElasticTseeInstaller = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.elasticsearch }}
	ComponentElasticsearch = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.elasticsearch }}
	ComponentElasticsearchFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "eck-elasticsearch-operator" }}
	ComponentECKElasticsearchOperator = Component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "elasticsearch-operator" }}
	ComponentElasticsearchOperator = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "es-proxy" }}
	ComponentEsProxy = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "es-gateway" }}
	ComponentESGateway = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "linseed" }}
	ComponentLinseed = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.fluentd }}
	ComponentFluentd = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "fluentd-windows" }}
	ComponentFluentdWindows = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.guardian }}
	ComponentGuardian = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "intrusion-detection-controller" }}
	ComponentIntrusionDetectionController = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "security-event-webhooks-processor" }}
	ComponentSecurityEventWebhooksProcessor = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.kibana }}
	ComponentKibana = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-manager" }}
	ComponentManager = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "dex" }}
	ComponentDex = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.voltron }}
	ComponentManagerProxy = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "packetcapture" }}
	ComponentPacketCapture = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "policy-recommendation" }}
	ComponentPolicyRecommendation = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "egress-gateway" }}
	ComponentEgressGateway = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "l7-collector" }}
	ComponentL7Collector = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "envoy" }}
	ComponentEnvoyProxy = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "dikastes" }}
	ComponentDikastes = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "coreos-prometheus" }}
	ComponentCoreOSPrometheus = Component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "prometheus" }}
	ComponentPrometheus = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-prometheus-service" }}
	ComponentTigeraPrometheusService = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "coreos-alertmanager" }}
	ComponentCoreOSAlertmanager = Component{
		Version:  "{{ .Version }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "alertmanager" }}
	ComponentPrometheusAlertmanager = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-queryserver" }}
	ComponentQueryServer = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-kube-controllers" }}
	ComponentTigeraKubeControllers = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-node" }}
	ComponentTigeraNode = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "cnx-node-windows" }}
	ComponentTigeraNodeWindows = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.typha }}
	ComponentTigeraTypha = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-cni" }}
	ComponentTigeraCNI = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-cni" }}
	ComponentTigeraCNIFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "tigera-cni-windows" }}
	ComponentTigeraCNIWindows = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "elasticsearch-metrics" }}
	ComponentElasticsearchMetrics = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "flexvol" }}
	ComponentTigeraFlexVolume = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "csi" }}
	ComponentTigeraCSI = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "csi-node-driver-registrar" }}
	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
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
		ComponentTigeraFlexVolume,
		ComponentTigeraCSI,
		ComponentTigeraCSINodeDriverRegistrar,
	}
)
