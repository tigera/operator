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
// config/calico_versions.yml

package components

var (
	CalicoRelease string = "{{ .Title }}"
{{ with index .Components "calico/cni" }}
	ComponentCalicoCNI = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoCNIFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components.cni }}
	ComponentCalicoCNI = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoCNIFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/cni-windows" }}
	ComponentCalicoCNIWindows = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components "cni-windows" }}
	ComponentCalicoCNIWindows = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "key-cert-provisioner" }}
	ComponentCalicoCSRInitContainer = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/kube-controllers" }}
	ComponentCalicoKubeControllers = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components "kube-controllers" }}
	ComponentCalicoKubeControllers = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components  "calico/node" }}
	ComponentCalicoNode = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoNodeFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components.node }}
	ComponentCalicoNode = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoNodeFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components  "calico/node-windows" }}
	ComponentCalicoNodeWindows = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components  "node-windows" }}
	ComponentCalicoNodeWindows = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with .Components.typha }}
	ComponentCalicoTypha = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoTyphaFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with .Components.flexvol }}
	ComponentCalicoFlexVolume = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/apiserver" }}
	ComponentCalicoAPIServer = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components.apiserver }}
	ComponentCalicoAPIServer = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/csi" }}
	ComponentCalicoCSI = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoCSIFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components.csi }}
	ComponentCalicoCSI = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoCSIFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "csi-node-driver-registrar" }}
	ComponentCalicoCSIRegistrar = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}

	ComponentCalicoCSIRegistrarFIPS = Component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/goldmane" }}
	ComponentCalicoGoldmane = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components.goldmane }}
	ComponentCalicoGoldmane = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/whisker" }}
	ComponentCalicoWhisker = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components.whisker }}
	ComponentCalicoWhisker = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/whisker-backend" }}
	ComponentCalicoWhiskerBackend = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components "whisker-backend" }}
	ComponentCalicoWhiskerBackend = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/envoy-gateway" }}
	ComponentCalicoEnvoyGateway = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components "envoy-gateway" }}
	ComponentCalicoEnvoyGateway = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/envoy-proxy" }}
	ComponentCalicoEnvoyProxy = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components "envoy-proxy" }}
	ComponentCalicoEnvoyProxy = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/envoy-ratelimit" }}
	ComponentCalicoEnvoyRatelimit = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components "envoy-ratelimit" }}
	ComponentCalicoEnvoyRatelimit = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}
{{ with index .Components "calico/guardian" }}
	ComponentCalicoGuardian = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end -}}
{{ with index .Components "guardian" }}
	ComponentCalicoGuardian = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  calicoVariant,
	}
{{- end }}

	CalicoImages = []Component{
		ComponentCalicoCNI,
		ComponentCalicoCNIFIPS,
		ComponentCalicoCNIWindows,
		ComponentCalicoCSRInitContainer,
		ComponentCalicoKubeControllers,
		ComponentCalicoKubeControllersFIPS,
		ComponentCalicoNode,
		ComponentCalicoNodeFIPS,
		ComponentCalicoNodeWindows,
		ComponentCalicoTypha,
		ComponentCalicoTyphaFIPS,
		ComponentCalicoFlexVolume,
		ComponentCalicoAPIServer,
		ComponentCalicoAPIServerFIPS,
		ComponentCalicoCSI,
		ComponentCalicoCSIFIPS,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoCSIRegistrarFIPS,
		ComponentCalicoGoldmane,
		ComponentCalicoWhisker,
		ComponentCalicoWhiskerBackend,
		ComponentCalicoEnvoyGateway,
		ComponentCalicoEnvoyProxy,
		ComponentCalicoEnvoyRatelimit,
		ComponentCalicoGuardian,
	}
)
