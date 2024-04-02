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
// config/calico_versions.yml

package components

import "github.com/tigera/operator/version"

var (
	CalicoRelease string = "{{ .Title }}"
{{ with index .Components "calico/cni" }}
	ComponentCalicoCNI = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/cni" }}
	ComponentCalicoCNIFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/cni-windows" }}
	ComponentCalicoCNIWindows = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "key-cert-provisioner" }}
	ComponentCalicoCSRInitContainer = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/kube-controllers" }}
	ComponentCalicoKubeControllers = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/kube-controllers" }}
	ComponentCalicoKubeControllersFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components  "calico/node" }}
	ComponentCalicoNode = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components  "calico/node" }}
	ComponentCalicoNodeFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components  "calico/node-windows" }}
	ComponentCalicoNodeWindows = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.typha }}
	ComponentCalicoTypha = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.typha }}
	ComponentCalicoTyphaFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with .Components.flexvol }}
	ComponentCalicoFlexVolume = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/apiserver"}}
	ComponentCalicoAPIServer = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/apiserver"}}
	ComponentCalicoAPIServerFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/csi"}}
	ComponentCalicoCSI = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "calico/csi"}}
	ComponentCalicoCSIFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "csi-node-driver-registrar"}}
	ComponentCalicoCSIRegistrar = component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
{{ with index .Components "csi-node-driver-registrar"}}
	ComponentCalicoCSIRegistrarFIPS = component{
		Version:  "{{ .Version }}-fips",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
	}
{{- end }}
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator",
	}

	CalicoImages = []component{
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
		ComponentOperatorInit,
		ComponentCalicoAPIServer,
		ComponentCalicoAPIServerFIPS,
		ComponentCalicoCSI,
		ComponentCalicoCSIFIPS,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoCSIRegistrarFIPS,
	}
)
