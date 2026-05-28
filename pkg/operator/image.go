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

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
)

// ImageOverride returns the component image to use for an installation, and
// false to decline (leaving the default in place). Implementations self-gate
// on in.Variant.
type ImageOverride func(in *operatorv1.InstallationSpec) (components.Component, bool)

var imageOverrides = map[string]ImageOverride{}

// OverrideImage registers an image override under key. The key is the render
// component's image identifier (e.g. "node").
func OverrideImage(key string, fn ImageOverride) {
	imageOverrides[key] = fn
}

// ResolveImage returns the override registered for key if it applies to in,
// otherwise def. Render components call this inside ResolveImages.
func ResolveImage(key string, def components.Component, in *operatorv1.InstallationSpec) components.Component {
	if fn, ok := imageOverrides[key]; ok {
		if c, override := fn(in); override {
			return c
		}
	}
	return def
}
