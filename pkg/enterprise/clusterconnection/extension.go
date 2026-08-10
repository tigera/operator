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
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Extension is the Calico Enterprise behavior for the clusterconnection controller
// and the guardian components it renders.
type Extension struct {
	variant operatorv1.ProductVariant
}

var _ extensions.ClusterConnectionExtension = &Extension{}

// New returns the clusterconnection extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant) *Extension {
	return &Extension{variant: variant}
}

// Modify dispatches over the components the clusterconnection controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch t := c.(type) {
	case render.GuardianComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyGuardian(ri, t.GuardianConfig(), objs, del)
		})
	case render.GuardianPolicyComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyGuardianPolicy(ri, t.GuardianPolicyConfig(), objs, del)
		})
	default:
		return c
	}
}

func (e *Extension) validate(ctx context.Context, ci controller.Inputs) error {
	managementCluster, err := utils.GetManagementCluster(ctx, ci.Client)
	if err != nil {
		return fmt.Errorf("error reading ManagementCluster: %w", err)
	}
	if managementCluster != nil {
		return extensions.InvalidConfigf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
	}
	return nil
}

// ExtendInputs computes the Enterprise-specific Guardian inputs the controller
// reads back: the managed cluster version (CNXVersion) and whether the license
// permits the domain-based egress network policy. It creates no certificates, so it
// returns no managed keypairs. The OSS controller path supplies its own defaults
// when this hook is absent.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if err := e.validate(ctx, ci); err != nil {
		return ci, nil, err
	}

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
