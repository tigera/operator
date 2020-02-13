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

// GetImageReference returns the fully qualified image to use, including registry and version.
func GetImageReference(imageName string, registry string) string {
	// If a user supplied a registry, use that for all images.
	if registry != "" {
		return fmt.Sprintf("%s%s", registry, imageName)
	}

	// Otherwise, default the registry based on component.
	reg := TigeraRegistry
	switch imageName {
	case NodeImageNameCalico,
		CNIImageName,
		TyphaImageNameCalico,
		KubeControllersImageNameCalico,
		FlexVolumeImageName:

		reg = CalicoRegistry
	case ECKElasticsearchImageName, ECKOperatorImageName:
		reg = ECKRegistry
	}
	return fmt.Sprintf("%s%s", reg, imageName)
}
