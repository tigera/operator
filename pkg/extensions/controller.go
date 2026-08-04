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
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Controller is the extension surface for one controller, resolved once when that
// controller is built. Its zero value is inert, so the core operator and any
// controller a variant doesn't extend run the base behavior through the same code.
type Controller struct {
	ext       ControllerExtension
	images    *imageoverride.Overrides
	decorator Decorator
}

// For resolves the extension surface for the named controller. Nil-safe.
func (r *Registry) For(name controller.Name) Controller {
	if r == nil {
		return Controller{}
	}

	return Controller{
		ext:       r.controllers[name],
		images:    r.images,
		decorator: Decorator{variant: r.variant, modifiers: r.modifiers},
	}
}

// ExtendInputs does the controller-side reconcile work and returns the inputs the
// render phase consumes, plus the keypairs the controller should manage.
func (c Controller) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if c.ext == nil {
		return ci, nil, nil
	}
	return c.ext.ExtendInputs(ctx, ci)
}

// Watches registers the watches the extension declares.
func (c Controller) Watches(ct ctrlruntime.Controller) error {
	w, ok := c.ext.(Watcher)
	if !ok {
		return nil
	}
	return w.Watches(ct)
}

// DefaultFelixConfiguration applies the extension's FelixConfiguration defaults,
// reporting whether it changed fc.
func (c Controller) DefaultFelixConfiguration(install *operatorv1.InstallationSpec, fc *v3.FelixConfiguration) (bool, error) {
	d, ok := c.ext.(FelixConfigDefaulter)
	if !ok {
		return false, nil
	}
	return d.DefaultFelixConfiguration(install, fc)
}

// ProductVersion is the product version to report in the Installation status.
func (c Controller) ProductVersion() string {
	v, ok := c.ext.(ProductVersion)
	if !ok {
		return components.CalicoRelease
	}
	return v.ProductVersion()
}

// Images is the image override table, which render resolves through directly.
func (c Controller) Images() *imageoverride.Overrides {
	return c.images
}

// Decorator applies the registered component modifiers, for handing to a component
// handler.
func (c Controller) Decorator() Decorator {
	return c.decorator
}
