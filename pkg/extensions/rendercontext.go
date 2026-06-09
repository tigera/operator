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
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// RenderContext carries reconcile-derived inputs from controllers into render
// modifiers. Core operator code never reads these fields - only registered
// modifiers do.
// Three kinds of value live here:
//   - raw cluster state gathered generically (Installation, FelixConfiguration,
//     ClusterDomain) that modifiers derive their own values from,
//   - controller-produced artifacts (TrustedBundle, NodePrometheusTLS) that can
//     only be created controller-side because they have cluster side effects, and
//   - Component, the per-component context the component being modified supplies
//     for config a modifier can't derive from the fields above.
type RenderContext struct {
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	ClusterDomain      string

	// TrustedBundle is the shared CA bundle for the calico-system namespace.
	TrustedBundle certificatemanagement.TrustedBundle

	// NodePrometheusTLS is created by the enterprise setup (it has cluster side
	// effects, so it can't be built in a modifier). The node modifier is its only
	// consumer: it mounts the keypair onto the daemonset and sets the
	// FELIX_PROMETHEUSREPORTER* certificate env vars.
	NodePrometheusTLS certificatemanagement.KeyPairInterface

	// Component is per-component context that the component being modified supplies
	// via render.ExtensionContextProvider - config a modifier needs but can't
	// derive from the fields above (e.g. a keypair the component's own controller
	// created, or a CR field only that controller reads). The componentHandler
	// sets it per component before applying the modifier; a modifier type-asserts
	// it to the component's own context type. Nil when the component supplies none.
	Component any
}
