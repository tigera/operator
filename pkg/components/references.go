// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package components

import (
	"fmt"
	"slices"
	"strings"

	operator "github.com/tigera/operator/api/v1"
)

type Component struct {
	// ImageName is the image name for this component (e.g., node, cni)
	ImageName string

	// ImagePath is the path to an image (e.g., tigera/, calico/).
	ImagePath string

	Version string

	// Registry is only used for developer workflows. For production builds, the registry
	// is always determined from user configuration. This field can be overridden
	// as part of a developer workflow to deploy custom dev images on an individual basis.
	Registry string
}

// FullImage is the image path and image name combined, without the registry or version.
func (c Component) Image() string {
	return fmt.Sprintf("%s%s", c.ImagePath, c.ImageName)
}

const UseDefault = "UseDefault"

// GetReference returns the fully qualified image to use, including registry and version.
func GetReference(c Component, registry, imagePath, imagePrefix string, is *operator.ImageSet) (string, error) {
	// If a user did not supply a registry, use the default registry
	// based on component
	if registry == "" || registry == UseDefault {
		switch {
		case slices.Contains(CalicoImages, c):
			registry = CalicoRegistry
		case c == ComponentOperatorInit:
			registry = InitRegistry
		default:
			registry = TigeraRegistry
		}

		// If the component asks for an explicit registry, and the user
		// did not provide a custom registry, use the one specified by
		// the component.
		if c.Registry != "" {
			registry = c.Registry
		}
	} else if !strings.HasSuffix(registry, "/") {
		// If the registry is explicitly set, make sure it ends with a slash so that the
		// image can be appended correctly below.
		registry = fmt.Sprintf("%s/", registry)
	}

	image := c.ImageName
	if imagePrefix != "" && imagePrefix != UseDefault {
		image = fmt.Sprintf("%s%s", imagePrefix, image)
	}
	if imagePath != "" && imagePath != UseDefault {
		// Ensure image path ends with a slash.
		if !strings.HasSuffix(imagePath, "/") {
			imagePath = fmt.Sprintf("%s/", imagePath)
		}
		image = fmt.Sprintf("%s%s", imagePath, image)
	} else {
		image = fmt.Sprintf("%s%s", c.ImagePath, image)
	}

	if is == nil {
		return fmt.Sprintf("%s%s:%s", registry, image, c.Version), nil
	}

	for _, img := range is.Spec.Images {
		if img.Image == c.Image() {
			return fmt.Sprintf("%s%s@%s", registry, image, img.Digest), nil
		}
	}

	return "", fmt.Errorf("ImageSet did not contain image %s", c.Image())
}
