// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package components

var (
	EnterpriseRelease string = "{{ .Title }}"
{{ with index .Components "cnx-apiserver" }}
	ComponentAPIServer = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "compliance-benchmarker" }}
	ComponentComplianceBenchmarker = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "compliance-controller" }}
	ComponentComplianceController = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "compliance-reporter" }}
	ComponentComplianceReporter = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "compliance-server" }}
	ComponentComplianceServer = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "compliance-snapshotter" }}
	ComponentComplianceSnapshotter = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "eck-elasticsearch" }}
	ComponentEckElasticsearch = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "eck-kibana" }}
	ComponentEckKibana = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "elastic-tsee-installer" }}
	ComponentElasticTseeInstaller = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.elasticsearch }}
	ComponentElasticsearch = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "elasticsearch-operator" }}
	ComponentElasticsearchOperator = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "es-curator" }}
	ComponentEsCurator = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "es-proxy" }}
	ComponentEsProxy = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "es-gateway" }}
	ComponentEsGateway = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.fluentd }}
	ComponentFluentd = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "fluentd-windows" }}
	ComponentFluentdWindows = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.guardian }}
	ComponentGuardian = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "intrusion-detection-controller" }}
	ComponentIntrusionDetectionController = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.kibana }}
	ComponentKibana = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "cnx-manager" }}
	ComponentManager = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "dex" }}
	ComponentDex = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.voltron }}
	ComponentManagerProxy = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "cnx-queryserver" }}
	ComponentQueryServer = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "cnx-kube-controllers" }}
	ComponentTigeraKubeControllers = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "cnx-node" }}
	ComponentTigeraNode = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.typha }}
	ComponentTigeraTypha = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "tigera-cni" }}
	ComponentTigeraCNI = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "cloud-controllers" }}
	ComponentCloudControllers = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "elasticsearch-metrics" }}
	ComponentElasticsearchMetrics = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}

	EnterpriseComponents = []component{
		ComponentAPIServer,
		ComponentComplianceBenchmarker,
		ComponentComplianceController,
		ComponentComplianceReporter,
		ComponentComplianceServer,
		ComponentComplianceSnapshotter,
		ComponentEckElasticsearch,
		ComponentEckKibana,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentEsCurator,
		ComponentEsProxy,
		ComponentFluentd,
		ComponentFluentdWindows,
		ComponentGuardian,
		ComponentIntrusionDetectionController,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentManagerProxy,
		ComponentQueryServer,
		ComponentTigeraKubeControllers,
		ComponentTigeraNode,
		ComponentTigeraTypha,
		ComponentTigeraCNI,
		ComponentCloudControllers,
		ComponentElasticsearchMetrics,
		ComponentEsGateway,
	}
)
