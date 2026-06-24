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
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/contexts"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// ControllerExtension extends a controller's reconcile: it validates the
// configuration and builds the RenderContext the render phase consumes. The core
// operator registers none and runs with the base behavior; an extension build
// registers one per controller it extends.
type ControllerExtension interface {
	// Validate rejects configuration the extension does not support, before any
	// rendering happens.
	Validate(cc contexts.ControllerContext) error

	// ExtendContext does the controller-side reconcile work the render phase
	// cannot, returning the RenderContext the render phase consumes plus any
	// keypairs the extension created that the controller should manage (add to
	// certificate management and BYO-expiry warnings), or an error that aborts the
	// reconcile.
	ExtendContext(cc contexts.ControllerContext) (render.RenderContext, []certificatemanagement.KeyPairInterface, error)
}

// Watcher is an optional companion to ControllerExtension. A controller's Add()
// calls Set.SetupWatches, which invokes Watches on any registered extension that
// implements this, so the extension registers the watches it needs (its CRs, its
// secrets) instead of the controller naming them.
type Watcher interface {
	Watches(c ctrlruntime.Controller) error
}

// FelixConfigDefaulter is an optional companion to ControllerExtension. A
// controller's FelixConfiguration defaulting calls Set.DefaultFelixConfiguration,
// which invokes this on a registered extension that implements it, so the variant's
// FelixConfiguration defaults (e.g. the provider-specific dnsTrustedServers) live in
// the extension instead of the controller. It returns whether it changed fc. Felix
// defaulting persists early in reconcile, before ExtendContext runs, so it can't fold
// into ExtendContext.
type FelixConfigDefaulter interface {
	DefaultFelixConfiguration(install *operatorv1.InstallationSpec, fc *v3.FelixConfiguration) (bool, error)
}
