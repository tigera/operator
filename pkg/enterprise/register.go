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
	"context"

	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common/discovery"
	"github.com/tigera/operator/pkg/enterprise/apiserver"
	"github.com/tigera/operator/pkg/enterprise/clusterconnection"
	"github.com/tigera/operator/pkg/enterprise/guardian"
	"github.com/tigera/operator/pkg/enterprise/installation"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/enterprise/typha"
	"github.com/tigera/operator/pkg/enterprise/windows"
	"github.com/tigera/operator/pkg/extensions"
)

// New builds the extension Set for the in-repo Calico Enterprise variant: the
// controller extension, every component modifier, and the image overrides. The
// operator is handed this Set at startup (the core operator is handed none).
// After the monorepo split this is what calico-private's main will construct
// instead. Each per-component subpackage registers its own controller hook and
// modifiers through its Register func.
func New() *extensions.Set {
	s := extensions.NewSet()
	s.RegisterOptions(computeOptions)

	ent := s.Variant(operatorv1.CalicoEnterprise)
	typha.Register(ent)
	installation.Register(ent)
	windows.Register(ent)
	guardian.Register(ent)
	apiserver.Register(ent)
	clusterconnection.Register(ent)

	// When the enterprise operator manages a Calico installation, clean up the
	// Enterprise objects left behind by a prior Enterprise installation.
	cal := s.Variant(operatorv1.Calico)
	apiserver.RegisterCalicoCleanup(cal)

	return s
}

// computeOptions discovers the Calico Enterprise controller-phase options at
// startup. extensions.Set.ComputeOptions runs it from main; the result rides on
// each ControllerContext for the enterprise hooks to read.
func computeOptions(ctx context.Context, cli kubernetes.Interface) (any, error) {
	multiTenant, err := discovery.MultiTenant(ctx, cli)
	if err != nil {
		return nil, err
	}
	return eoptions.Options{MultiTenant: multiTenant}, nil
}
