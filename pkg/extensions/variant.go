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
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
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
	variant    operatorv1.ProductVariant
	controller ControllerExtension
	modifiers  map[string]decorator
	images     *imageoverride.Overrides // shared with the owning Set
}

// decorator wraps a base component, returning one whose Objects() are augmented
// by a registered modifier.
type decorator func(base render.Component, rc RenderContext) render.Component

// Controller registers the variant's controller-side extension. A variant has
// at most one; registering replaces any prior one.
func (v *Variant) Controller(c ControllerExtension) {
	v.controller = c
}

// Image registers an image override for the named component.
func (v *Variant) Image(component string, image components.Component) {
	v.images.Register(v.variant, component, image)
}

// Modify registers a modifier for a component that needs no per-component
// config. For components whose modifier needs the component's own typed config,
// use RegisterModifier.
func (v *Variant) Modify(component string, m Modifier) {
	v.modifiers[component] = func(base render.Component, rc RenderContext) render.Component {
		return &decoratedComponent{Component: base, rc: rc, modify: m}
	}
}

// RegisterModifier registers a modifier for component whose modifier needs the
// component's own typed config. The component supplies it via
// render.ExtensionContextProvider; RegisterModifier asserts it to Cfg once, here,
// and hands the typed value to modify - so the modifier body needs no assertion.
// It is a free function because Go has no generic methods.
func RegisterModifier[Cfg any](
	v *Variant,
	component string,
	modify func(rc RenderContext, cfg Cfg, create, delete []client.Object) ([]client.Object, []client.Object),
) {
	v.modifiers[component] = func(base render.Component, rc RenderContext) render.Component {
		provider, ok := base.(render.ExtensionContextProvider)
		if !ok {
			logrus.Errorf("BUG: component %q has a registered modifier but provides no extension context; leaving it unmodified", component)
			return base
		}
		cfg, ok := provider.ExtensionContext().(Cfg)
		if !ok {
			var want Cfg
			logrus.Errorf("BUG: component %q extension context is %T, want %T; leaving it unmodified", component, provider.ExtensionContext(), want)
			return base
		}
		bound := func(rc RenderContext, create, delete []client.Object) ([]client.Object, []client.Object) {
			return modify(rc, cfg, create, delete)
		}
		return &decoratedComponent{Component: base, rc: rc, modify: bound}
	}
}

// decorate wraps component with the modifier registered for its extension key,
// or returns it unchanged when the component exposes no extension point or none
// is registered. Nil-safe.
func (v *Variant) decorate(component render.Component, rc RenderContext) render.Component {
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
	return build(component, rc)
}

// validate runs the controller extension's validation, or nil when the variant
// has none. Nil-safe.
func (v *Variant) validate(cc ControllerContext) error {
	if v == nil || v.controller == nil {
		return nil
	}
	return v.controller.Validate(cc)
}

// extendContext runs the controller extension, or returns the base render
// context and no managed keypairs when the variant has none. Nil-safe.
func (v *Variant) extendContext(cc ControllerContext) (RenderContext, []certificatemanagement.KeyPairInterface, error) {
	if v == nil || v.controller == nil {
		return cc.RenderContext, nil, nil
	}
	return v.controller.ExtendContext(cc)
}

// decoratedComponent is the render.Component produced by decorate: it renders
// its embedded base component and then runs the variant modifier over the
// result. It embeds the base render.Component, so ResolveImages, SupportedOSType,
// and Ready delegate to the base; only Objects is augmented.
type decoratedComponent struct {
	render.Component
	rc     RenderContext
	modify Modifier
}

func (d *decoratedComponent) Objects() ([]client.Object, []client.Object) {
	create, del := d.Component.Objects()
	return d.modify(d.rc, create, del)
}
