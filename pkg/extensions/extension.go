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
)

// Extension is everything a variant layers onto one render component. Every
// field is optional: a component that only needs a different image sets Image
// and leaves Modify nil, and vice versa. This is the single registration a
// variant makes per component, so all of that component's variance lives in one
// place.
type Extension struct {
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

// ApplyModifiers runs the modifier registered for the named component and the
// installation's variant over the create and delete lists, returning them
// unchanged when none is registered (or when no installation is set). Safe to
// call on a nil Set, which is a no-op - the core operator registers no
// modifiers.
func (s *Set) ApplyModifiers(component string, ctx RenderContext, create, delete []client.Object) ([]client.Object, []client.Object) {
	if s == nil || ctx.Installation == nil {
		return create, delete
	}
	if fn, ok := s.modifiers[modifierKey{ctx.Installation.Variant, component}]; ok {
		create, delete = fn(ctx, create, delete)
	}
	return create, delete
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
