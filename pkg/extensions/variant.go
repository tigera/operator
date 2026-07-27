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
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Variant bundles everything that extends the core operator for one product
// variant: the controller-side hook, the per-component modifiers, and the image
// overrides. The Set selects one Variant per reconcile from the installation's
// variant, so within a Variant there is at most one extension per component and
// nothing here is itself keyed by variant.
type Variant struct {
	variant     operatorv1.ProductVariant
	controllers map[controller.Name]ControllerExtension
	modifiers   map[string]decorator
	images      *imageoverride.Overrides // shared with the owning Set
}

// decorator wraps a base component, returning one whose Objects() are augmented
// by a registered modifier.
type decorator func(base render.Component, ri render.Inputs) render.Component

// Controller registers the variant's controller-side extension for the named
// controller. A controller has at most one; registering replaces any prior one.
func (v *Variant) Controller(name controller.Name, c ControllerExtension) {
	v.controllers[name] = c
}

// Image registers an image override for the named component.
func (v *Variant) Image(component string, image components.Component) {
	v.images.Register(v.variant, component, image)
}

// Modify registers v's modifier for the component that owns key. Cfg comes from the
// key, not from modify, so a modifier written against a different component does not
// compile. Modify asserts the component's inputs to Cfg once, here, so the modifier
// body needs no assertion. Free function because Go has no generic methods.
func Modify[Cfg any](
	v *Variant,
	key render.ModifierKey[Cfg],
	modify func(ri render.Inputs, cfg Cfg, create, delete []client.Object) ([]client.Object, []client.Object),
) {
	v.modifiers[key.String()] = func(base render.Component, ri render.Inputs) render.Component {
		// Both of these mean the component and its key disagree, which the component's
		// own package controls and no caller can recover from.
		provider, ok := base.(render.ExtensionInputsProvider)
		if !ok {
			panic(fmt.Sprintf("BUG: component %q has a registered modifier but provides no extension inputs", key))
		}
		cfg, ok := provider.ExtensionInputs().(Cfg)
		if !ok {
			var want Cfg
			panic(fmt.Sprintf("BUG: component %q extension inputs are %T, want %T", key, provider.ExtensionInputs(), want))
		}
		bound := func(ri render.Inputs, create, delete []client.Object) ([]client.Object, []client.Object) {
			return modify(ri, cfg, create, delete)
		}
		return &decoratedComponent{Component: base, ri: ri, modify: bound}
	}
}

// decorate wraps component with the modifier registered for its extension key,
// or returns it unchanged when the component exposes no extension point or none
// is registered. Nil-safe.
func (v *Variant) decorate(component render.Component, ri render.Inputs) render.Component {
	if v == nil {
		return component
	}
	ext, ok := component.(render.Extensible)
	if !ok {
		return component
	}
	build, ok := v.modifiers[ext.ModifierKey()]
	if !ok {
		return component
	}
	return build(component, ri)
}

// validate runs the ci.Controller extension's validation, or nil when the
// variant has none for it. Nil-safe.
func (v *Variant) validate(ctx context.Context, ci controller.Inputs) error {
	if v == nil || v.controllers[ci.Controller] == nil {
		return nil
	}
	return v.controllers[ci.Controller].Validate(ctx, ci)
}

// extendInputs runs the ci.Controller extension, or returns ci unchanged and no
// managed keypairs when the variant has none for it. Nil-safe.
func (v *Variant) extendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if v == nil || v.controllers[ci.Controller] == nil {
		return ci, nil, nil
	}
	return v.controllers[ci.Controller].ExtendInputs(ctx, ci)
}

// decoratedComponent is the render.Component produced by decorate: it renders
// its embedded base component and then runs the variant modifier over the
// result. It embeds the base render.Component, so ResolveImages, SupportedOSType,
// and Ready delegate to the base; only Objects is augmented.
type decoratedComponent struct {
	render.Component
	ri     render.Inputs
	modify modifier
}

func (d *decoratedComponent) Objects() ([]client.Object, []client.Object) {
	create, del := d.Component.Objects()
	return d.modify(d.ri, create, del)
}
