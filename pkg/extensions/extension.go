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

	"github.com/tigera/operator/pkg/render"
)

// modifier post-processes the objects a render component produced, with the
// component's typed inputs already bound in by Modify. It may mutate matched
// objects and append to either list (deletes clean up what a prior variant left
// behind). It runs only for the variant it is registered under.
type modifier func(ri render.Inputs, create, delete []client.Object) (newCreate, newDelete []client.Object)

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
