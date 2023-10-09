// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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

package imageset

import (
	"context"
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
)

// ApplyImageSet gets the appropriate ImageSet, validates the ImageSet, and calls ResolveImages
// passing in the ImageSet on each of the comps.
func ApplyImageSet(ctx context.Context, c client.Client, v operator.ProductVariant, comps ...render.Component) error {
	imageSet, err := GetImageSet(ctx, c, v)
	if err != nil {
		return err
	}

	if err = ValidateImageSet(imageSet); err != nil {
		return err
	}

	return ResolveImages(imageSet, comps...)
}

// Utility function to add a watch on ImageSet resources.
func AddImageSetWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operator.ImageSet{}}, &handler.EnqueueRequestForObject{})
}

func getSetName(v operator.ProductVariant) string {
	if v == operator.TigeraSecureEnterprise {
		return fmt.Sprintf("enterprise-%s", components.EnterpriseRelease)
	}
	return fmt.Sprintf("calico-%s", components.CalicoRelease)
}

// GetImageSet finds the ImageSet for specified variant.
func GetImageSet(ctx context.Context, cli client.Client, v operator.ProductVariant) (*operator.ImageSet, error) {
	isl := &operator.ImageSetList{}

	// List the ImageSets because if any exist then we will require the
	// existence of one for the expected version of the operator running
	// and the variant configured.
	err := cli.List(ctx, isl)
	if err != nil {
		return nil, fmt.Errorf("failed to get imageset list: %s", err)
	}

	if len(isl.Items) == 0 {
		// No ImageSets and that is fine
		return nil, nil
	}

	setName := getSetName(v)

	for _, is := range isl.Items {
		if is.Name == setName {
			return &is, nil
		}
	}

	return nil, fmt.Errorf("ImageSets exist but none with the expected name %s", setName)
}

// ValidateImageSet validates that all the images in an ImageSet are images the operator uses
// and that the Digest is in an allowed format.
func ValidateImageSet(is *operator.ImageSet) error {
	// None is valid
	if is == nil {
		return nil
	}
	unknownImages := []string{}
	for _, img := range is.Spec.Images {
		valid := false
		for _, x := range components.CalicoImages {
			if img.Image == x.Image {
				valid = true
				break
			}
		}
		if valid {
			continue
		}
		for _, x := range components.EnterpriseImages {
			if img.Image == x.Image {
				valid = true
				break
			}
		}
		if valid {
			continue
		}

		for _, x := range components.CommonImages {
			if img.Image == x.Image {
				valid = true
				break
			}
		}
		if !valid {
			unknownImages = append(unknownImages, img.Image)
		}
	}

	invalidDigests := []string{}
	for _, img := range is.Spec.Images {
		if !strings.HasPrefix(img.Digest, "sha256:") {
			invalidDigests = append(invalidDigests, fmt.Sprintf("%s@%s", img.Image, img.Digest))
		}
	}

	if len(unknownImages) == 0 && len(invalidDigests) == 0 {
		return nil
	}

	errMsgs := []string{}

	if len(unknownImages) != 0 {
		errMsgs = []string{fmt.Sprintf("unexpected images: %s", strings.Join(unknownImages, ", "))}
	}

	if len(invalidDigests) != 0 {
		errMsgs = append(errMsgs, fmt.Sprintf("bad digest images: %s", strings.Join(invalidDigests, ", ")))
	}
	return fmt.Errorf("ImageSet %s: %s", is.Name, strings.Join(errMsgs, "; "))
}

func ResolveImages(is *operator.ImageSet, comps ...render.Component) error {
	errMsgs := []string{}
	for _, comp := range comps {
		err := comp.ResolveImages(is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) == 0 {
		return nil
	}

	return fmt.Errorf("Invalid ImageSet: %s", strings.Join(errMsgs, ", "))
}
