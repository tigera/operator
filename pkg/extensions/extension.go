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
)

// Modifier post-processes the objects a render component produced. It receives
// the component's create and delete lists and returns the (possibly extended)
// lists. A modifier may mutate matched objects, append objects to create, and
// append objects to delete (e.g. to clean up resources a prior variant left
// behind). It runs only for the variant it is registered under, so it need not
// re-check the variant.
type Modifier func(ctx RenderContext, create, delete []client.Object) (newCreate, newDelete []client.Object)

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
