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
// Two kinds of value live here:
//   - raw cluster state gathered generically (Installation, FelixConfiguration,
//     ClusterDomain) that modifiers derive their own values from, and
//   - controller-produced artifacts (TrustedBundle, NodePrometheusTLS) that can
//     only be created controller-side because they have cluster side effects.
type RenderContext struct {
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	ClusterDomain      string

	// TrustedBundle is the shared CA bundle for the calico-system namespace.
	TrustedBundle certificatemanagement.TrustedBundle

	// NodePrometheusTLS is created by the enterprise RenderContextFactory (it has
	// cluster side effects, so it can't be built in a modifier). Two consumers
	// read it: the installation controller passes it to the node configuration
	// (PrometheusServerTLS) so the keypair is mounted, and the node modifier uses
	// it to set the FELIX_PROMETHEUSREPORTER* certificate env vars.
	NodePrometheusTLS certificatemanagement.KeyPairInterface
}
