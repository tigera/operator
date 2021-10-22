// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

import "fmt"

// Default registries for Calico and Tigera.
const (
	CloudRegistry = "gcr.io/tigera-tesla/"
)

var ElasticExternal bool = false

func cloudRegistry(c component, registry, version string) (string, string) {
	// If not external ES then use regular images
	if !ElasticExternal {
		return registry, version
	}
	if registry == "" || registry == UseDefault {
		switch c {
		case ComponentEsProxy, ComponentIntrusionDetectionController, ComponentTigeraKubeControllers:
			registry = CloudRegistry
		}
	}
	switch c {
	case ComponentEsProxy, ComponentIntrusionDetectionController, ComponentTigeraKubeControllers:
		version = fmt.Sprintf("tesla-%s", version)
	}
	return registry, version
}
