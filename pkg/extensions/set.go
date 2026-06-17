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
)

// Set is the collection of variant extensions the operator runs with: the
// per-variant setups, the per-component modifiers, and the image overrides. The
// core operator runs with a nil/empty Set; an extension build (Calico
// Enterprise) constructs a populated one and hands it in through
// options.ControllerOptions. This replaces what used to be package-level
// registries, so nothing is wired by import side effect.
//
// The zero value is not usable; build one with NewSet. The methods that read it
// (BuildContext, ApplyModifiers, ResolveImage, Images) are nil-safe so the core
// operator can pass a nil Set and get base behavior.
type Set struct {
	setups    map[operatorv1.ProductVariant]Setup
	modifiers map[modifierKey]Modifier
	images    *imageoverride.Overrides
}

// NewSet returns an empty Set ready to register extensions into.
func NewSet() *Set {
	return &Set{
		setups:    map[operatorv1.ProductVariant]Setup{},
		modifiers: map[modifierKey]Modifier{},
		images:    imageoverride.New(),
	}
}

// Register installs e as the extension for the named component under the given
// variant. A (variant, component) pair has at most one extension; registration
// replaces any prior one. The image override and the modifier are stored
// separately, so a component can set either field or both.
func (s *Set) Register(variant operatorv1.ProductVariant, component string, e Extension) {
	if e.Image != nil {
		s.images.Register(variant, component, e.Image)
	}
	if e.Modify != nil {
		s.modifiers[modifierKey{variant, component}] = e.Modify
	}
}

// RegisterSetup installs setup as the controller-side setup phase for the given
// variant. Registration replaces any prior setup for that variant.
func (s *Set) RegisterSetup(variant operatorv1.ProductVariant, setup Setup) {
	s.setups[variant] = setup
}

// Images returns the image overrides. The render package resolves a component's
// image through these directly (the imageoverride leaf, so render need not
// import extensions). Safe to call on a nil Set, which returns nil overrides
// that resolve to the default image.
func (s *Set) Images() *imageoverride.Overrides {
	if s == nil {
		return nil
	}
	return s.images
}

// ResolveImage resolves key for the installation through the image overrides,
// returning def when no override applies. Safe to call on a nil Set.
func (s *Set) ResolveImage(key string, def components.Component, in *operatorv1.InstallationSpec) components.Component {
	return s.Images().Resolve(key, def, in)
}
