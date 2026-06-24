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
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/contexts"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Set is all the variant extensions the operator runs with, indexed by product
// variant. The core operator runs with a nil Set; an extension build (e.g.
// Calico Enterprise) constructs a populated one and hands it in through
// options.ControllerOptions. This replaces what used to be package-level
// registries, so nothing is wired by import side effect.
//
// Per reconcile the controller selects one Variant from the installation's
// variant. The methods the controller calls (Decorate, Validate, ExtendContext,
// Images, ResolveImage) are nil-safe, so the core operator's nil Set yields base
// behavior.
type Set struct {
	variants map[operatorv1.ProductVariant]*Variant
	images   *imageoverride.Overrides
}

// NewSet returns an empty Set ready to register variant extensions into.
func NewSet() *Set {
	return &Set{
		variants: map[operatorv1.ProductVariant]*Variant{},
		images:   imageoverride.New(),
	}
}

// Variant returns the extension bundle for v, creating an empty one if needed.
// Used at registration time to build up a variant's extensions.
func (s *Set) Variant(v operatorv1.ProductVariant) *Variant {
	if s.variants[v] == nil {
		s.variants[v] = &Variant{
			variant:     v,
			controllers: map[contexts.ControllerName]ControllerExtension{},
			modifiers:   map[string]decorator{},
			images:      s.images,
		}
	}
	return s.variants[v]
}

// variant looks up the bundle for v, returning nil when none is registered.
// Nil-safe.
func (s *Set) variant(v operatorv1.ProductVariant) *Variant {
	if s == nil {
		return nil
	}
	return s.variants[v]
}

// Decorate wraps component with the extension registered for it under the
// installation's variant, so that when the handler renders the component its
// objects are post-processed by that modifier. A decorated component is itself a
// render.Component, so it flows through the component handler like any other.
// Returns component unchanged when no extension applies. Nil-safe.
func (s *Set) Decorate(component render.Component, ctx render.RenderContext) render.Component {
	if ctx.Installation == nil {
		return component
	}
	return s.variant(ctx.Installation.Variant).decorate(component, ctx)
}

// Validate runs the cc.Controller extension's validation for the installation's
// variant, or returns nil when no extension is registered. Nil-safe.
func (s *Set) Validate(cc contexts.ControllerContext) error {
	if cc.Installation == nil {
		return nil
	}
	return s.variant(cc.Installation.Variant).validate(cc)
}

// ExtendContext runs the cc.Controller extension for the installation's variant
// and returns the resulting render.RenderContext plus any keypairs the extension wants
// the controller to manage, or the base render context and no keypairs when no
// extension is registered. Nil-safe.
func (s *Set) ExtendContext(cc contexts.ControllerContext) (render.RenderContext, []certificatemanagement.KeyPairInterface, error) {
	if cc.Installation == nil {
		return cc.RenderContext, nil, nil
	}
	return s.variant(cc.Installation.Variant).extendContext(cc)
}

// SetupWatches registers the watches every variant's extension declares for the
// named controller. It runs at controller startup, which is variant-agnostic, so
// it registers the union across variants (in practice the one active extension
// build's). Nil-safe.
func (s *Set) SetupWatches(controller contexts.ControllerName, c ctrlruntime.Controller) error {
	if s == nil {
		return nil
	}
	for _, v := range s.variants {
		w, ok := v.controllers[controller].(Watcher)
		if !ok {
			continue
		}
		if err := w.Watches(c); err != nil {
			return err
		}
	}
	return nil
}

// DefaultFelixConfiguration runs the named controller's extension FelixConfiguration
// defaulting for the installation's variant, returning whether it changed fc. The
// extension implements the optional FelixConfigDefaulter companion; when it doesn't
// (or no extension is registered) this is a no-op. Nil-safe.
func (s *Set) DefaultFelixConfiguration(controller contexts.ControllerName, install *operatorv1.InstallationSpec, fc *v3.FelixConfiguration) (bool, error) {
	if install == nil {
		return false, nil
	}
	v := s.variant(install.Variant)
	if v == nil {
		return false, nil
	}
	d, ok := v.controllers[controller].(FelixConfigDefaulter)
	if !ok {
		return false, nil
	}
	return d.DefaultFelixConfiguration(install, fc)
}

// Images returns the shared image override table. The render package resolves a
// component's image through it directly (the imageoverride leaf, so render need
// not import extensions). Nil-safe, returning nil overrides that resolve to the
// default image.
func (s *Set) Images() *imageoverride.Overrides {
	if s == nil {
		return nil
	}
	return s.images
}

// ResolveImage resolves key for the installation through the image overrides,
// returning def when no override applies. Nil-safe.
func (s *Set) ResolveImage(key string, def components.Component, in *operatorv1.InstallationSpec) components.Component {
	return s.Images().Resolve(key, def, in)
}
