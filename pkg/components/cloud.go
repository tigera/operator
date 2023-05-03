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
	ComponentImageAssuranceApiProxy = component{
		Version: "v1.6.2",
		Image:   "tigera/image-assurance-api-proxy",
	}

	ComponentImageAssuranceScanner = component{
		Version: "v1.6.2",
		Image:   "tigera/image-assurance-scanner",
	}

	ComponentImageAssuranceRuntimeCleaner = component{
		Version: "v1.6.2",
		Image:   "tigera/image-assurance-runtime-cleaner",
	}

	ComponentSasha = component{
		Version: "v1.6.0",
		Image:   "tigera/sasha",
	}

	ComponentThreatId = component{
		Version: "v1.6.0",
		Image:   "tigera/threat-identification",
	}

	ComponentCloudRBACApi = component{
		Version: "v0.1.1-0-g74b6dbe",
		Image:   "tigera/cc-rbac-api",
	}

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
