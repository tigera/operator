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

// Modifier post-processes the objects a render component produced. It may mutate
// matched objects and/or append additional objects, and must return the
// (possibly extended) slice. A modifier is registered per variant, so it only
// runs for its own variant and need not re-check it.
type Modifier func(ctx RenderContext, objs []client.Object) []client.Object

type modifierKey struct {
	variant   operatorv1.ProductVariant
	component string
}

var modifiers = map[modifierKey]Modifier{}

// Modify registers fn as the modifier for the named component under the given
// variant. A (variant, component) pair has at most one modifier; it handles all
// of that component's extension-specific mutations for that variant.
// Registration replaces any prior modifier, so it is idempotent and safe to
// call more than once.
func Modify(variant operatorv1.ProductVariant, component string, fn Modifier) {
	modifiers[modifierKey{variant, component}] = fn
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

// ResetForTest clears every registry: modifiers, image overrides, and the
// render context builder. Test-only.
func ResetForTest() {
	modifiers = map[modifierKey]Modifier{}
	renderContextBuilders = map[operatorv1.ProductVariant]RenderContextBuilder{}
	imageoverride.ResetForTest()
}
