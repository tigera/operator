// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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
// config/cloud_versions.yml

package components

var (
{{- with index .Components "image-assurance-api-proxy" }}
	ComponentImageAssuranceApiProxy = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "image-assurance-scanner" }}
	ComponentImageAssuranceScanner = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "image-assurance-runtime-cleaner" }}
	ComponentImageAssuranceRuntimeCleaner = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "sasha" }}
	ComponentSasha = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "threat-id" }}
	ComponentThreatId = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}
{{ with index .Components "cloud-rbac-api" }}
	ComponentCloudRBACApi = component{
		Version: "{{ .Version }}",
		Image:   "{{ .Image }}",
	}
{{- end }}

	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	CloudImages = []component{
		ComponentImageAssuranceApiProxy,
		ComponentImageAssuranceScanner,
		ComponentImageAssuranceRuntimeCleaner,
		ComponentSasha,
		ComponentThreatId,
		ComponentCloudRBACApi,
	}
)
