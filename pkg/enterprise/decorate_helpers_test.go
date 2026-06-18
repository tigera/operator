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

package enterprise_test

import (
	client "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

// stubExtComponent adapts raw object lists to a render.Component so a registered
// extension can be exercised through Set.Decorate, the same seam the component
// handler uses. key selects the extension; extCtx is delivered as the component's
// ExtensionContext (the typed config a RegisterModifier modifier reads).
type stubExtComponent struct {
	key            string
	extCtx         any
	create, delete []client.Object
}

func (s stubExtComponent) ResolveImages(*operatorv1.ImageSet) error {
	return nil
}

func (s stubExtComponent) Objects() ([]client.Object, []client.Object) {
	return s.create, s.delete
}

func (s stubExtComponent) Ready() bool {
	return true
}

func (s stubExtComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (s stubExtComponent) ModifierKey() string {
	return s.key
}

func (s stubExtComponent) ExtensionContext() any {
	return s.extCtx
}

// applyExtensions decorates a stub component holding the given objects with the
// extension registered under key, then renders it. For a modifier that needs the
// component's typed config, use applyExtensionsWithContext.
func applyExtensions(s *extensions.Set, key string, ctx extensions.RenderContext, create, del []client.Object) ([]client.Object, []client.Object) {
	return applyExtensionsWithContext(s, key, ctx, nil, create, del)
}

// applyExtensionsWithContext is applyExtensions for a modifier that reads the
// component's typed config: extCtx is delivered as the stub's ExtensionContext.
func applyExtensionsWithContext(s *extensions.Set, key string, ctx extensions.RenderContext, extCtx any, create, del []client.Object) ([]client.Object, []client.Object) {
	stub := stubExtComponent{key: key, extCtx: extCtx, create: create, delete: del}
	return s.Decorate(stub, ctx).Objects()
}
