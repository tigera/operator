// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	"strings"

	operator "github.com/tigera/operator/api/v1"
)

type component struct {
	// Image is the full image path and name for this component (e.g., tigera/cnx-node, calico/cni)
	Image   string
	Version string

	// Registry is only used for developer workflows. For production builds, the registry
	// is always determined from user configuration. This field can be overridden
	// as part of a developer workflow to deploy custom dev images on an individual basis.
	Registry string
}

const UseDefault = "UseDefault"

// GetReference returns the fully qualified image to use, including registry and version.
func GetReference(c component, registry, imagePath, imagePrefix string, is *operator.ImageSet) (string, error) {
	// If a user did not supply a registry, use the default registry
	// based on component
	if registry == "" || registry == UseDefault {
		switch c {
		case ComponentCalicoNode,
			ComponentCalicoNodeWindows,
			ComponentCalicoCNI,
			ComponentCalicoCNIFIPS,
			ComponentCalicoCNIWindows,
			ComponentCalicoTypha,
			ComponentCalicoTyphaFIPS,
			ComponentCalicoKubeControllers,
			ComponentCalicoKubeControllersFIPS,
			ComponentFlexVolume,
			ComponentCalicoAPIServer,
			ComponentCalicoAPIServerFIPS,
			ComponentCalicoCSI,
			ComponentCalicoCSIFIPS,
			ComponentCalicoCSIRegistrar,
			ComponentCalicoCSIRegistrarFIPS:

			registry = CalicoRegistry
		case ComponentOperatorInit:
			registry = InitRegistry
		case ComponentCSRInitContainer:
			registry = CSRInitRegistry
		default:
			registry = TigeraRegistry
		}

		// If the component asks for an explicit registry, and the user
		// did not provide a custom registry, use the one specified by
		// the component.
		if c.Registry != "" {
			registry = c.Registry
		}
	}

	image := c.Image
	if imagePrefix != "" && imagePrefix != UseDefault {
		image = insertPrefix(image, imagePrefix)
	}
	if imagePath != "" && imagePath != UseDefault {
		image = ReplaceImagePath(image, imagePath)
	}

	if is == nil {
		return fmt.Sprintf("%s%s:%s", registry, image, c.Version), nil
	}

	for _, img := range is.Spec.Images {
		if img.Image == c.Image {
			return fmt.Sprintf("%s%s@%s", registry, image, img.Digest), nil
		}
	}

	return "", fmt.Errorf("ImageSet did not contain image %s", c.Image)
}

func ReplaceImagePath(image, imagePath string) string {
	subs := strings.SplitAfterN(image, "/", 2)
	if len(subs) == 2 {
		return fmt.Sprintf("%s/%s", imagePath, subs[1])
	}
	return fmt.Sprintf("%s/%s", imagePath, subs[0])
}

func insertPrefix(image, prefix string) string {
	subs := strings.Split(image, "/")
	if len(subs) == 1 {
		// The given image is just a single image with no prefix.
		return fmt.Sprintf("%s%s", prefix, image)
	}
	subs = append(subs[:len(subs)-1], fmt.Sprintf("%s%s", prefix, subs[len(subs)-1]))
	return strings.Join(subs, "/")
}
