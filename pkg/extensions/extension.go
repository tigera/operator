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
	"github.com/tigera/operator/pkg/imageoverride"
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

// Modifier post-processes the objects a render component produced. It may mutate
// matched objects and/or append additional objects, and must return the
// (possibly extended) slice. A modifier runs only for the variant it was
// registered under, so it need not re-check the variant.
type Modifier func(ctx RenderContext, objs []client.Object) []client.Object

type modifierKey struct {
	variant   operatorv1.ProductVariant
	component string
}

var modifiers = map[modifierKey]Modifier{}

// Register installs e as the extension for the named component under the given
// variant. A (variant, component) pair has at most one extension; registration
// replaces any prior one, so it is idempotent and safe to call more than once.
// The image override lives in the imageoverride leaf (so the render package can
// resolve it without an import cycle); the modifier lives here.
func Register(variant operatorv1.ProductVariant, component string, e Extension) {
	if e.Image != nil {
		imageoverride.Register(variant, component, e.Image)
	}
	if e.Modify != nil {
		modifiers[modifierKey{variant, component}] = e.Modify
	}
}

// ApplyModifiers runs the modifier registered for the named component and the
// installation's variant over objs, returning objs unchanged when none is
// registered (or when no installation is set).
func ApplyModifiers(component string, ctx RenderContext, objs []client.Object) []client.Object {
	if ctx.Installation == nil {
		return objs
	}
	if fn, ok := modifiers[modifierKey{ctx.Installation.Variant, component}]; ok {
		objs = fn(ctx, objs)
	}
	return objs
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

// ResetForTest clears every registry: modifiers, image overrides, and variant
// setups. Test-only.
func ResetForTest() {
	modifiers = map[modifierKey]Modifier{}
	setups = map[operatorv1.ProductVariant]Setup{}
	imageoverride.ResetForTest()
}
