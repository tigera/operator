// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func PatchFelixConfiguration(ctx context.Context, c client.Client, patchFn func(fc *crdv1.FelixConfiguration) (bool, error)) (*crdv1.FelixConfiguration, error) {
	// Fetch any existing default FelixConfiguration object.
	fc := &crdv1.FelixConfiguration{}
	err := c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
	if err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to read FelixConfiguration: %w", err)
	}

	// Create a base state for the upcoming patch operation.
	patchFrom := client.MergeFrom(fc.DeepCopy())

	// Apply desired changes to the FelixConfiguration.
	updated, err := patchFn(fc)
	if err != nil {
		return nil, err
	}
	if updated {
		// Apply the patch.
		if fc.ResourceVersion == "" {
			fc.ObjectMeta.Name = "default"
			if err := c.Create(ctx, fc); err != nil {
				return nil, err
			}
		} else {
			if err := c.Patch(ctx, fc, patchFrom); err != nil {
				return nil, err
			}
		}
	}

	return fc, nil
}
