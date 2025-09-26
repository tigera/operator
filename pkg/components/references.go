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

	Version string

	// Registry is only used for developer workflows. For production builds, the registry
	// is always determined from user configuration. This field can be overridden
	// as part of a developer workflow to deploy custom dev images on an individual basis.
	Registry string
}

// FullImage is the image path and image name combined, without the registry or version.
func (c Component) Image() string {
	_, imagePath := getDefaults(c)
	return fmt.Sprintf("%s%s", imagePath, c.ImageName)
}

const UseDefault = "UseDefault"

// getDefaults returns the default registry and imagePath for a given component.
// This is used when no registry is explicitly defined by the component
// and user does not explicitly specify a registry or imagePath.
func getDefaults(c Component) (registry string, imagePath string) {
	switch {
	case slices.Contains(CalicoImages, c):
		registry = CalicoRegistry
		imagePath = CalicoImagePath
	case c == ComponentOperatorInit:
		registry = InitRegistry
		imagePath = InitImagePath
	default:
		registry = TigeraRegistry
		imagePath = TigeraImagePath
	}
	return
}

// GetReference returns the fully qualified image to use, including registry and version.
func GetReference(c Component, registry, imagePath, imagePrefix string, is *operator.ImageSet) (string, error) {
	defaultRegistry, defaultImagePath := getDefaults(c)

	// If a user did not supply a registry, use the default registry
	if registry == "" || registry == UseDefault {
		registry = defaultRegistry
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

	// If a user supplies an imaagePrefix, prepend it to the image name.
	imageName := c.ImageName
	if imagePrefix != "" && imagePrefix != UseDefault {
		imageName = fmt.Sprintf("%s%s", imagePrefix, imageName)
	}

	// If a user did not supply an imagePath, use the default imagePath
	if imagePath == "" || imagePath == UseDefault {
		imagePath = defaultImagePath
	} else if !strings.HasSuffix(imagePath, "/") {
		// If the imagePath is explicitly set, make sure it ends with a slash so that the
		// image can be appended correctly below.
		imagePath = fmt.Sprintf("%s/", imagePath)
	}

	if is == nil {
		return fmt.Sprintf("%s%s%s:%s", registry, imagePath, imageName, c.Version), nil
	}

	for _, img := range is.Spec.Images {
		if img.Image == fmt.Sprintf("%s%s", defaultImagePath, c.ImageName) {
			return fmt.Sprintf("%s%s%s@%s", registry, imagePath, imageName, img.Digest), nil
		}
	}

	return "", fmt.Errorf("ImageSet did not contain image %s", c.Image())
}
