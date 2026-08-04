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
// ExtIn is delivered as the component's ExtensionInputs (the typed inputs the
// modifier reads).
type StubComponent struct {
	Key            string
	ExtIn          any
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

func (s StubComponent) ExtensionInputs() any {
	return s.ExtIn
}

// ApplyExtensions decorates a stub component holding the given objects with the
// extension registered under key, then renders it. The stub hands the modifier the
// zero value of the key's inputs type; when the modifier reads real inputs, use
// ApplyExtensionsWithInputs.
func ApplyExtensions[Cfg any](r *extensions.Registry, key render.ModifierKey[Cfg], ri render.Inputs, create, del []client.Object) ([]client.Object, []client.Object) {
	var zero Cfg
	return ApplyExtensionsWithInputs(r, key, ri, zero, create, del)
}

// ApplyExtensionsWithInputs is ApplyExtensions for a modifier that reads the
// component's inputs. Their type comes from the key, so a test can't hand a
// modifier inputs of the wrong shape.
func ApplyExtensionsWithInputs[Cfg any](r *extensions.Registry, key render.ModifierKey[Cfg], ri render.Inputs, extIn Cfg, create, del []client.Object) ([]client.Object, []client.Object) {
	stub := StubComponent{Key: key.String(), ExtIn: extIn, Create: create, Delete: del}
	return r.Decorator().Decorate(stub, ri).Objects()
}
