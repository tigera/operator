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

package operator

import "sigs.k8s.io/controller-runtime/pkg/client"

// PatchFunc post-processes the objects a render component produced. It may
// mutate matched objects and/or append additional objects, and must return the
// (possibly extended) slice. Implementations self-gate on ctx.Installation.Variant.
type PatchFunc func(ctx Context, objs []client.Object) []client.Object

var patches = map[string][]PatchFunc{}

// Patch registers fn to run against the named component's objects. Multiple
// patches may be registered for the same component; they run in registration order.
func Patch(component string, fn PatchFunc) {
	patches[component] = append(patches[component], fn)
}

// ApplyPatches runs every patch registered for the named component over objs.
func ApplyPatches(component string, ctx Context, objs []client.Object) []client.Object {
	for _, fn := range patches[component] {
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

// ResetForTest clears all registries. Test-only.
func ResetForTest() {
	patches = map[string][]PatchFunc{}
	imageOverrides = map[string]ImageOverride{}
}
