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

import "github.com/tigera/operator/version"

var (
	CalicoRelease string = "{{ .Title }}"
{{ with index .Components "calico/cni" }}
	ComponentCalicoCNI = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "calico/kube-controllers" }}
	ComponentCalicoKubeControllers = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components  "calico/node" }}
	ComponentCalicoNode = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.typha }}
	ComponentCalicoTypha = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.flexvol }}
	ComponentFlexVolume = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with .Components.apiserver}}
	ComponentCalicoAPIServer = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator",
	}

	CalicoComponents = []component{
		ComponentCalicoCNI,
		ComponentCalicoKubeControllers,
		ComponentCalicoNode,
		ComponentCalicoTypha,
		ComponentFlexVolume,
		ComponentOperatorInit,
		ComponentCalicoAPIServer,
	}
)
