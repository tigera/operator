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

package enterprise

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise/apiserver"
	"github.com/tigera/operator/pkg/enterprise/clusterconnection"
	"github.com/tigera/operator/pkg/enterprise/guardian"
	"github.com/tigera/operator/pkg/enterprise/installation"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/enterprise/typha"
	"github.com/tigera/operator/pkg/enterprise/windows"
	"github.com/tigera/operator/pkg/extensions"
)

// New builds the extension registry for the in-repo Calico Enterprise variant:
// the controller extensions, the component modifiers, and the image overrides.
// The operator is handed this registry at startup (the core operator is handed
// none). After the monorepo split this is what calico-private's main will
// construct instead. Each per-component subpackage registers its own controller
// hook and modifiers through its Register func.
//
// variant is the variant the operator resolved at startup and runs as for its
// lifetime, so New registers only what that variant extends. o is resolved once by
// the caller and held by the hooks that need it.
func New(variant operatorv1.ProductVariant, o eoptions.Options) *extensions.Registry {
	r := extensions.NewRegistry(variant)
	switch variant {
	case operatorv1.CalicoEnterprise:
		typha.Register(r)
		installation.Register(r)
		windows.Register(r)
		guardian.Register(r)
		apiserver.Register(r, o)
		clusterconnection.Register(r)
	case operatorv1.Calico:
		// The Enterprise operator managing a Calico installation cleans up the
		// Enterprise objects a prior Enterprise installation left behind.
		apiserver.RegisterCalicoCleanup(r)
	}

	return r
}
