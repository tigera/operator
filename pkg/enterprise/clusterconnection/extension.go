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

package clusterconnection

import (
	"context"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Register wires the clusterconnection controller hook into the variant.
func Register(r *extensions.Registry) {
	r.RegisterController(controller.ClusterConnection, clusterConnectionControllerExtension{})
}

// clusterConnectionControllerExtension is the Calico Enterprise controller-side hook
// for the clusterconnection (ManagementClusterConnection) controller.
type clusterConnectionControllerExtension struct{}

// Validate rejects clusterconnection configuration Calico Enterprise does not
// support: a cluster cannot be both a management cluster and a managed cluster.
func (clusterConnectionControllerExtension) Validate(ctx context.Context, ci controller.Inputs) error {
	managementCluster, err := utils.GetManagementCluster(ctx, ci.Client)
	if err != nil {
		return fmt.Errorf("error reading ManagementCluster: %w", err)
	}
	if managementCluster != nil {
		return fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
	}
	return nil
}

// ExtendInputs computes the Enterprise-specific Guardian inputs the controller
// reads back: the managed cluster version (CNXVersion) and whether the license
// permits the domain-based egress network policy. It creates no certificates, so it
// returns no managed keypairs. The OSS controller path supplies its own defaults
// when this hook is absent.
func (clusterConnectionControllerExtension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	clusterInformation, err := utils.FetchClusterInformation(ctx, ci.Client)
	if err != nil {
		return ci, nil, fmt.Errorf("error querying ClusterInformation: %w", err)
	}

	// Ensure the license can support enterprise policy before enabling the
	// domain-based egress rules. A missing license simply leaves them disabled.
	var includeEgressNetworkPolicy bool
	if license, err := utils.FetchLicenseKey(ctx, ci.Client); err == nil {
		includeEgressNetworkPolicy = utils.IsFeatureActive(license, common.EgressAccessControlFeature)
	} else if !k8serrors.IsNotFound(err) {
		return ci, nil, fmt.Errorf("error querying license: %w", err)
	}

	ci.RenderInputs.Extension = render.GuardianRenderData{
		Version:                    clusterInformation.Spec.CNXVersion,
		IncludeEgressNetworkPolicy: includeEgressNetworkPolicy,
	}
	return ci, nil, nil
}
