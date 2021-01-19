// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
{{- with index . "cnx-apiserver" }}
	ComponentAPIServer = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "compliance-benchmarker" }}
	ComponentComplianceBenchmarker = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "compliance-controller" }}
	ComponentComplianceController = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "compliance-reporter" }}
	ComponentComplianceReporter = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "compliance-server" }}
	ComponentComplianceServer = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "compliance-snapshotter" }}
	ComponentComplianceSnapshotter = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "eck-elasticsearch" }}
	ComponentEckElasticsearch = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "eck-kibana" }}
	ComponentEckKibana = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "elastic-tsee-installer" }}
	ComponentElasticTseeInstaller = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .elasticsearch }}
	ComponentElasticsearch = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "elasticsearch-operator" }}
	ComponentElasticsearchOperator = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "es-curator" }}
	ComponentEsCurator = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "es-proxy" }}
	ComponentEsProxy = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .fluentd }}
	ComponentFluentd = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .guardian }}
	ComponentGuardian = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "intrusion-detection-controller" }}
	ComponentIntrusionDetectionController = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .kibana }}
	ComponentKibana = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "cnx-manager" }}
	ComponentManager = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "dex" }}
	ComponentDex = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .voltron }}
	ComponentManagerProxy = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "cnx-queryserver" }}
	ComponentQueryServer = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "cnx-kube-controllers" }}
	ComponentTigeraKubeControllers = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "cnx-node" }}
	ComponentTigeraNode = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .typha }}
	ComponentTigeraTypha = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "tigera-cni" }}
	ComponentTigeraCNI = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index . "cloud-controllers" }}
	ComponentCloudControllers = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
)
