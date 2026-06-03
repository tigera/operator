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

	"github.com/tigera/operator/pkg/imageoverride"
)

// Modifier post-processes the objects a render component produced. It may mutate
// matched objects and/or append additional objects, and must return the
// (possibly extended) slice. Implementations self-gate on ctx.Installation.Variant.
type Modifier func(ctx RenderContext, objs []client.Object) []client.Object

var modifiers = map[string]Modifier{}

// Modify registers fn as the modifier for the named component. A component has
// at most one modifier; the modifier handles all of that component's
// extension-specific mutations. Registration replaces any prior modifier, so it
// is idempotent and safe to call more than once - matching the image-override
// registry rather than stacking duplicate work.
func Modify(component string, fn Modifier) {
	modifiers[component] = fn
}

// ApplyModifiers runs the modifier registered for the named component over objs,
// returning objs unchanged when none is registered.
func ApplyModifiers(component string, ctx RenderContext, objs []client.Object) []client.Object {
	if fn, ok := modifiers[component]; ok {
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
// render context factory. Test-only.
func ResetForTest() {
	modifiers = map[string]Modifier{}
	renderContextFactory = defaultFactory{}
	imageoverride.ResetForTest()
}
