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

	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
)

func ApplyImageSet(ctx context.Context, c client.Client, i *operator.InstallationSpec, components []render.Component) error {
	// If any image sets exist
	//   fetch image set for Variant and Version
	//   if error return it (includes if there was none matching
	// else if no image sets
	//   return nil
	for _, component := range components {
		err := component.ValidateImages(imageSet)
		// accumulate any errors
	}
	// return errors if they existed
	return fmt.Errorf("Not Implemented")
}
