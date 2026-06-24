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

package render

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// RenderContext carries reconcile-derived inputs from controllers into render
// modifiers. Core operator code never reads these fields - only registered
// modifiers do. It carries raw cluster state gathered generically (Installation,
// FelixConfiguration, ClusterDomain) that modifiers derive their own values from,
// the shared TrustedBundle, and an opaque Extension slot for controller-produced
// data specific to one extension.
//
// It lives in render (not the extensions package) because it is the render-phase
// input a modifier consumes - the render-side corollary to the controller-phase
// ControllerContext. The extensions package wires modifiers to it; it is not
// itself part of the extension mechanism.
//
// Per-component config a modifier needs but can't derive from these fields is
// not carried here; it flows to the modifier as a typed argument (see
// extensions.RegisterModifier), supplied by the component via
// ExtensionContextProvider.
type RenderContext struct {
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	ClusterDomain      string

	// TrustedBundle is the shared CA bundle for the calico-system namespace.
	TrustedBundle certificatemanagement.TrustedBundle

	// Extension is opaque, extension-owned data that the controller extension
	// produced for its own modifiers - typically an artifact that can only be
	// created controller-side because it has cluster side effects (e.g. a keypair).
	// The extension that set it type-asserts it back out in its modifiers; core
	// code never reads it. Nil when no extension is active.
	Extension any
}
