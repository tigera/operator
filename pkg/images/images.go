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

// Package images is a leaf package (no render/operator dependencies) that holds the
// per-variant image table. The render package imports it to resolve a component's
// image without depending on pkg/extensions, which would cycle.
package images

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
)

type tableKey struct {
	variant operatorv1.ProductVariant
	key     string
}

// Table maps an image key, per variant, to the image it resolves to, so the render
// package never branches on variant. Registry and image path are applied downstream.
type Table struct {
	m map[tableKey]components.Component
}

// New returns an empty Table.
func New() *Table {
	return &Table{m: map[tableKey]components.Component{}}
}

// Register stores image under key for the given variant.
func (o *Table) Register(variant operatorv1.ProductVariant, key string, image components.Component) {
	o.m[tableKey{variant, key}] = image
}

// Resolve returns the image registered for key under the installation's variant,
// otherwise def. It is safe to call on a nil *Table, which always returns def.
func (o *Table) Resolve(key string, def components.Component, in *operatorv1.InstallationSpec) components.Component {
	if o == nil || in == nil {
		return def
	}
	if image, ok := o.m[tableKey{in.Variant, key}]; ok {
		return image
	}
	return def
}
