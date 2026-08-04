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
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/render"
)

// Decorator applies the registered component modifiers on the way to a component
// handler. Its zero value decorates nothing, which is what the core operator wants.
type Decorator struct {
	modifiers map[string]decorator
}

// Decorate wraps component with the modifier registered for its extension key, so
// that when the handler renders the component its objects are post-processed. A
// decorated component is itself a render.Component, so it flows through the handler
// like any other. Returns component unchanged when it exposes no extension point or
// nothing is registered for it.
func (d Decorator) Decorate(component render.Component, ri render.Inputs) render.Component {
	ext, ok := component.(render.Extensible)
	if !ok {
		return component
	}

	build, ok := d.modifiers[ext.ModifierKey()]
	if !ok {
		return component
	}
	return build(component, ri)
}

// decorator wraps a base component, returning one whose Objects() are augmented
// by a registered modifier.
type decorator func(base render.Component, ri render.Inputs) render.Component

// newDecorator binds key's typed inputs into modify, so the modifier body needs no
// type assertion.
func newDecorator[Cfg any](
	key render.ModifierKey[Cfg],
	modify func(ri render.Inputs, cfg Cfg, create, delete []client.Object) ([]client.Object, []client.Object),
) decorator {
	return func(base render.Component, ri render.Inputs) render.Component {
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

// decoratedComponent is the render.Component produced by Decorate: it renders its
// embedded base component and then runs the modifier over the result. It embeds the
// base render.Component, so ResolveImages, SupportedOSType, and Ready delegate to
// the base; only Objects is augmented.
type decoratedComponent struct {
	render.Component
	ri     render.Inputs
	modify modifier
}

func (d *decoratedComponent) Objects() ([]client.Object, []client.Object) {
	create, del := d.Component.Objects()
	return d.modify(d.ri, create, del)
}
