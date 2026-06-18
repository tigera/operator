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
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
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
			variant:   v,
			modifiers: map[string]decorator{},
			images:    s.images,
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
func (s *Set) Decorate(component render.Component, ctx RenderContext) render.Component {
	if ctx.Installation == nil {
		return component
	}
	return s.variant(ctx.Installation.Variant).decorate(component, ctx)
}

// Validate runs the controller extension's validation for the installation's
// variant, or returns nil when no extension is registered. Nil-safe.
func (s *Set) Validate(cc ControllerContext) error {
	if cc.Installation == nil {
		return nil
	}
	return s.variant(cc.Installation.Variant).validate(cc)
}

// ExtendContext runs the controller extension for the installation's variant and
// returns the resulting RenderContext, or the base render context when no
// extension is registered. Nil-safe.
func (s *Set) ExtendContext(cc ControllerContext) (RenderContext, error) {
	if cc.Installation == nil {
		return cc.RenderContext, nil
	}
	return s.variant(cc.Installation.Variant).extendContext(cc)
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
