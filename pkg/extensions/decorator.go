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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
)

// Decorator applies the registered component modifiers. Its zero value decorates
// nothing.
type Decorator struct {
	variant   operatorv1.ProductVariant
	modifiers map[string]decorator
}

// Decorate wraps component with the modifier registered for its extension key. The
// result is itself a render.Component, so it flows through the handler like any other.
func (d Decorator) Decorate(component render.Component, ri render.Inputs) render.Component {
	// The registry is built for the variant resolved at startup. Until the process
	// restarts onto a new one, an Installation asking for a different variant gets the
	// base render, matching how the image overrides resolve.
	if ri.Installation == nil || ri.Installation.Variant != d.variant {
		return component
	}

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

// decorator wraps a base component in one whose Objects() a modifier augments.
type decorator func(base render.Component, ri render.Inputs) render.Component

// newDecorator binds key's typed inputs into modify.
func newDecorator[Cfg any](
	key render.ModifierKey[Cfg],
	modify func(ri render.Inputs, cfg Cfg, create, delete []client.Object) ([]client.Object, []client.Object),
) decorator {
	return func(base render.Component, ri render.Inputs) render.Component {
		// The component and its key disagree, which no caller can recover from.
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

// decoratedComponent renders its embedded base component and then runs the modifier
// over the result. Everything but Objects delegates to the base.
type decoratedComponent struct {
	render.Component
	ri     render.Inputs
	modify modifier
}

func (d *decoratedComponent) Objects() ([]client.Object, []client.Object) {
	create, del := d.Component.Objects()
	return d.modify(d.ri, create, del)
}
