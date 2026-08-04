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

package extensions

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

type noopExtension struct{}

func (noopExtension) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	return ci, nil, nil
}

type noopWatcher struct{}

func (noopWatcher) Watches(ctrlruntime.Controller) error {
	return nil
}

type noopFelixConfigDefaulter struct{}

func (noopFelixConfigDefaulter) DefaultFelixConfiguration(*operatorv1.InstallationSpec, *v3.FelixConfiguration) (bool, error) {
	return false, nil
}
