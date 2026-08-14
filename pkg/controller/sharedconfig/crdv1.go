// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package sharedconfig

import (
	"context"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller/utils"
)

// crdV1Writer writes through crd.projectcalico.org/v1, the API group used in aggregated apiserver mode.
type crdV1Writer struct {
	client client.Client
}

var _ Writer = &crdV1Writer{}

func (w *crdV1Writer) UpdateFelixConfiguration(ctx context.Context, updateFn func(fc *v3.FelixConfiguration) (bool, error)) (*v3.FelixConfiguration, error) {
	// Fetch any existing default FelixConfiguration object.
	fc := &v3.FelixConfiguration{}
	err := w.client.Get(ctx, types.NamespacedName{Name: "default"}, fc)
	if err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to read FelixConfiguration: %w", err)
	}

	// Create a base state for the upcoming patch operation.
	patchFrom := client.MergeFrom(fc.DeepCopy())

	if err = utils.RestoreV3Metadata(fc); err != nil {
		return nil, err
	}

	// Apply desired changes to the FelixConfiguration.
	updated, err := updateFn(fc)
	if err != nil {
		return nil, err
	}
	if updated {
		// Apply the patch.
		if fc.ResourceVersion == "" {
			fc.Name = "default"
			if err := w.client.Create(ctx, fc); err != nil {
				return nil, err
			}
		} else {
			if err := w.client.Patch(ctx, fc, patchFrom); err != nil {
				return nil, err
			}
		}
	}

	return fc, nil
}
