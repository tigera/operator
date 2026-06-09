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

// Package imageoverride is a leaf package (no render/operator dependencies)
// that holds the image override registry. Both pkg/operator and pkg/render
// import it to avoid the render→operator→render import cycle.
package imageoverride

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
)

// Override selects the component image to use for an installation.
type Override func(in *operatorv1.InstallationSpec) components.Component

type overrideKey struct {
	variant operatorv1.ProductVariant
	key     string
}

var registry = map[overrideKey]Override{}

// Register stores fn under key for the given variant. The key is the render
// component's image identifier (e.g. "node").
func Register(variant operatorv1.ProductVariant, key string, fn Override) {
	registry[overrideKey{variant, key}] = fn
}

// Resolve returns the override registered for key under the installation's
// variant, otherwise def.
func Resolve(key string, def components.Component, in *operatorv1.InstallationSpec) components.Component {
	if in == nil {
		return def
	}
	if fn, ok := registry[overrideKey{in.Variant, key}]; ok {
		return fn(in)
	}
	return def
}

// ResetForTest clears the registry. Test-only.
func ResetForTest() {
	registry = map[overrideKey]Override{}
}
