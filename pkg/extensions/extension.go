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
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
)

// ComponentExtension is everything a variant layers onto one render component.
// Every field is optional: a component that only needs a different image sets
// Image and leaves Modify nil, and vice versa. This is the single registration a
// variant makes per component, so all of that component's variance lives in one
// place.
type ComponentExtension struct {
	// Image overrides the component's image. Resolved during ResolveImages, in
	// the render package, via the imageoverride leaf.
	Image ImageOverride

	// Modify post-processes the component's rendered objects, after Objects().
	Modify Modifier
}

// Modifier post-processes the objects a render component produced. It receives
// the component's create and delete lists and returns the (possibly extended)
// lists. A modifier may mutate matched objects, append objects to create, and
// append objects to delete (e.g. to clean up resources another variant left
// behind). A modifier runs only for the variant it was registered under, so it
// need not re-check the variant.
type Modifier func(ctx RenderContext, create, delete []client.Object) (newCreate, newDelete []client.Object)

type modifierKey struct {
	variant   operatorv1.ProductVariant
	component string
}

// Decorate wraps component with the variant extension registered for it, so
// that when the handler renders the component its objects are post-processed by
// the modifier registered for the component and the installation's variant. A
// decorated component is itself a render.Component, so it flows through the
// component handler exactly like any other. Returns component unchanged when it
// exposes no extension point, when no modifier is registered for it, when no
// installation is set, or on a nil Set (the core operator registers no
// extensions).
func (s *Set) Decorate(component render.Component, ctx RenderContext) render.Component {
	if s == nil || ctx.Installation == nil {
		return component
	}
	ext, ok := component.(render.Extensible)
	if !ok {
		return component
	}
	modify, ok := s.modifiers[modifierKey{ctx.Installation.Variant, ext.ModifierKey()}]
	if !ok {
		return component
	}
	if p, ok := component.(render.ExtensionContextProvider); ok {
		ctx.Component = p.ExtensionContext()
	}
	return &decoratedComponent{Component: component, ctx: ctx, modify: modify}
}

// decoratedComponent is the render.Component produced by Decorate: it renders
// its embedded base component and then runs the variant modifier over the
// result. It embeds the base render.Component, so ResolveImages, SupportedOSType,
// and Ready delegate to the base; only Objects is augmented.
type decoratedComponent struct {
	render.Component
	ctx    RenderContext
	modify Modifier
}

func (d *decoratedComponent) Objects() ([]client.Object, []client.Object) {
	create, del := d.Component.Objects()
	return d.modify(d.ctx, create, del)
}

// FindObject returns the first object of type T with the given name.
func FindObject[T client.Object](objs []client.Object, name string) (T, bool) {
	var zero T
	for _, o := range objs {
		if t, ok := o.(T); ok && o.GetName() == name {
			return t, true
		}
	}
	return zero, false
}
