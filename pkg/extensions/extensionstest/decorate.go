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

// Package extensionstest holds shared helpers for exercising a registered
// extension through the same Set.Decorate seam the component handler uses. It is
// test support imported by the extension test suites (extensions, render, and the
// per-component enterprise packages), so the helper lives once instead of being
// copied into each test package.
package extensionstest

import (
	client "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

// StubComponent adapts raw object lists to a render.Component so a registered
// extension can be exercised through Set.Decorate. Key selects the extension;
// ExtCtx is delivered as the component's ExtensionContext (the typed config a
// RegisterModifier modifier reads).
type StubComponent struct {
	Key            string
	ExtCtx         any
	Create, Delete []client.Object
}

func (s StubComponent) ResolveImages(*operatorv1.ImageSet) error {
	return nil
}

func (s StubComponent) Objects() ([]client.Object, []client.Object) {
	return s.Create, s.Delete
}

func (s StubComponent) Ready() bool {
	return true
}

func (s StubComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (s StubComponent) ModifierKey() string {
	return s.Key
}

func (s StubComponent) ExtensionContext() any {
	return s.ExtCtx
}

// ApplyExtensions decorates a stub component holding the given objects with the
// extension registered under key, then renders it. For a modifier that needs the
// component's typed config, use ApplyExtensionsWithContext.
func ApplyExtensions(s *extensions.Set, key string, rc render.RenderContext, create, del []client.Object) ([]client.Object, []client.Object) {
	return ApplyExtensionsWithContext(s, key, rc, nil, create, del)
}

// ApplyExtensionsWithContext is ApplyExtensions for a modifier that reads the
// component's typed config: extCtx is delivered as the stub's ExtensionContext.
func ApplyExtensionsWithContext(s *extensions.Set, key string, rc render.RenderContext, extCtx any, create, del []client.Object) ([]client.Object, []client.Object) {
	stub := StubComponent{Key: key, ExtCtx: extCtx, Create: create, Delete: del}
	return s.Decorate(stub, rc).Objects()
}
