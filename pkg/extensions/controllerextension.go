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

// ControllerExtension builds the Inputs the render phase consumes. The core operator
// registers none and runs with the base behavior; an extension build registers one
// per controller it extends.
type ControllerExtension interface {
	// ExtendInputs does the controller-side reconcile work the render phase
	// cannot, returning the updated Inputs (its embedded Inputs is
	// what the render phase consumes) plus any keypairs the extension created that the
	// controller should manage (add to certificate management and BYO-expiry
	// warnings), or an error that aborts the reconcile. Configuration the extension
	// does not support is rejected here too, with InvalidConfigf.
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error)
}

// Watcher is an optional companion a ControllerExtension may implement, so the
// extension registers the watches it needs instead of the controller naming them.
type Watcher interface {
	Watches(c ctrlruntime.Controller) error
}

// FelixConfigDefaulter is an optional companion a ControllerExtension may implement
// to default FelixConfiguration fields, returning whether it changed fc. It can't
// fold into ExtendInputs, which runs after Felix defaulting persists.
type FelixConfigDefaulter interface {
	DefaultFelixConfiguration(install *operatorv1.InstallationSpec, fc *v3.FelixConfiguration) (bool, error)
}
