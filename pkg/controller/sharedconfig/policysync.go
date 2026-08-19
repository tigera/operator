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

package sharedconfig

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
)

// PolicySyncFieldManager owns spec.policySyncPathPrefix for every feature needing it, so
// no controller can clear another's claim.
const PolicySyncFieldManager = "policy-sync"

const policySyncPath = "spec.policySyncPathPrefix"

// DeclarePolicySyncPathPrefix declares the socket path. Every caller reads all four CRs, so
// one field manager can own it.
func DeclarePolicySyncPathPrefix(ctx context.Context, c client.Client) DeclareFelixConfiguration {
	return func(_ *v3.FelixConfiguration) (*FelixConfigurationDeclaration, error) {
		needed, err := policySyncRequired(ctx, c)
		if err != nil {
			return nil, err
		}

		d := &FelixConfigurationDeclaration{
			Manager: PolicySyncFieldManager,
			Owned:   &v3.FelixConfiguration{},
			// A user who points Felix somewhere else keeps their path.
			Policies: map[string]ConflictPolicy{policySyncPath: ConflictDefer},
		}
		if needed {
			d.Owned.Spec.PolicySyncPathPrefix = utils.DefaultPolicySyncPrefix
		}
		return d, nil
	}
}

// policySyncRequired reports whether any feature still needs Felix's policy-sync socket.
func policySyncRequired(ctx context.Context, c client.Client) (bool, error) {
	al, err := eutils.GetApplicationLayer(ctx, c)
	if err != nil {
		return false, err
	}
	if utils.ApplicationLayerRequiresPolicySync(al) {
		return true, nil
	}

	gw, err := utils.GetGatewayAPI(ctx, c)
	if err != nil {
		return false, err
	}
	if utils.GatewayAPIRequiresPolicySync(gw) {
		return true, nil
	}

	egws, err := utils.ListEgressGateways(ctx, c)
	if err != nil {
		return false, err
	}
	for _, egw := range egws {
		if egw.DeletionTimestamp.IsZero() {
			return true, nil
		}
	}

	return istioRequiresPolicySync(ctx, c)
}

// istioRequiresPolicySync reads the variant from the Installation spec, not its status, to
// track the renderer.
func istioRequiresPolicySync(ctx context.Context, c client.Client) (bool, error) {
	istioCR, err := utils.GetIstio(ctx, c)
	if err != nil || istioCR == nil {
		return false, err
	}

	installationSpec, err := utils.GetInstallationSpec(ctx, c)
	if err != nil && !errors.IsNotFound(err) {
		return false, err
	}
	var variant operatorv1.ProductVariant
	if installationSpec != nil {
		variant = installationSpec.Variant
	}
	return utils.IstioRequiresPolicySync(istioCR, variant), nil
}
