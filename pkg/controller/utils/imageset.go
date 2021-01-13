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

package utils

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

// ApplyImageSet gets the appropriate ImageSet and applies it to
// the components passed in.
func ApplyImageSet(ctx context.Context, c client.Client, v operator.ProductVariant, comps ...render.Component) error {

	imageSet, err := getImageSet(ctx, c, v)
	if err != nil {
		return err
	}

	if err = validateImageSet(imageSet); err != nil {
		return err
	}

	errMsgs := []string{}
	for _, component := range comps {
		err = component.ResolveImages(imageSet)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) == 0 {
		return nil
	}

	return fmt.Errorf("Invalid ImageSet: %s", strings.Join(errMsgs, ", "))
}

func AddImageSetWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operator.ImageSet{}}, &handler.EnqueueRequestForObject{})
}

func getSetName(v operator.ProductVariant) string {
	setName := fmt.Sprintf("calico-%s", components.CalicoRelease)
	if v == operator.TigeraSecureEnterprise {
		setName = fmt.Sprintf("enterprise-%s", components.EnterpriseRelease)
	}
	return setName
}

// getImageSet finds the ImageSet CR for specified variant and for the correct .
func getImageSet(ctx context.Context, cli client.Client, v operator.ProductVariant) (*operator.ImageSet, error) {
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

func validateImageSet(is *operator.ImageSet) error {
	if is == nil {
		return nil
	}
	invalidImages := []string{}
	for _, img := range is.Spec.Images {
		valid := false
		for _, x := range components.CalicoComponents {
			if img.Image == x.Image {
				valid = true
				break
			}
		}
		if valid {
			continue
		}
		for _, x := range components.EnterpriseComponents {
			if img.Image == x.Image {
				valid = true
				break
			}
		}
		if !valid {
			invalidImages = append(invalidImages, img.Image)
		}
	}

	if len(invalidImages) == 0 {
		return nil
	}

	return fmt.Errorf("unexpected images in ImageSet %s: %s", is.Name, strings.Join(invalidImages, ", "))
}
