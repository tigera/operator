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

import (
	"fmt"
)

type component struct {
	Image   string
	Version string
	Digest  string
}

// GetReference returns the fully qualified image to use, including registry and version.
func GetReference(c component, registry string) string {
	// If a user did not supply a registry, use the default registry
	// based on component
	if registry == "" {
		switch c {
		case ComponentCalicoNode,
			ComponentCalicoCNI,
			ComponentCalicoTypha,
			ComponentCalicoKubeControllers,
			ComponentFlexVolume:

			registry = CalicoRegistry
		case ComponentElasticsearch, ComponentElasticsearchOperator:
			registry = ECKRegistry
		default:
			registry = TigeraRegistry
		}
	}

	return fmt.Sprintf("%s%s@%s", registry, c.Image, c.Digest)
}

// GetOperatorInitReference returns the fully qualified image to use, including registry and version
// for the operatorInit image.
//
// Deprecated: GetOperatorInitReference exists to solve a complex dependency where the digest of the operator
// init image isn't known until it's built, and it's code and docker image share this repository. This function
// should go away once operatorInit logic is moved into the operator.
func GetOperatorInitReference(registry string) string {
	// If a user did not supply a registry, use the default registry
	// based on component
	if registry == "" {
		registry = TigeraRegistry
	}

	return fmt.Sprintf("%s%s:%s", registry, ComponentOperatorInit.Image, ComponentOperatorInit.Version)
}
