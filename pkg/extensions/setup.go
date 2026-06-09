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
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Inputs is the reconcile state a Setup builds a RenderContext from. The
// installation controller populates it directly. It carries both the values
// that flow straight into the RenderContext and the side-effecting dependencies
// (Client, CertificateManager) a setup needs to produce controller-side
// artifacts.
type Inputs struct {
	Ctx                context.Context
	Client             client.Client
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	CertificateManager certificatemanager.CertificateManager
	TrustedBundle      certificatemanagement.TrustedBundle
	ClusterDomain      string
}

// Setup is a variant's controller-side reconcile phase. It performs the work
// modifiers can't (creating certificates, extending the trusted bundle,
// validating config) and returns the RenderContext that is then handed to that
// variant's modifiers - or an error that aborts the reconcile.
//
// This is the generic seam controllers use to extend base operator behavior;
// its first consumer is Calico Enterprise, but nothing here is enterprise
// specific. A setup runs only for the variant it was registered under, so it
// need not re-check the variant.
type Setup func(in Inputs) (RenderContext, error)

// BaseRenderContext maps the generically-gathered inputs onto a RenderContext.
// Every setup builds on it, so the base fields are assembled in exactly one
// place. A setup layers its side-effect artifacts (e.g. NodePrometheusTLS) on
// top of the returned value.
func BaseRenderContext(in Inputs) RenderContext {
	return RenderContext{
		Installation:       in.Installation,
		FelixConfiguration: in.FelixConfiguration,
		ClusterDomain:      in.ClusterDomain,
		TrustedBundle:      in.TrustedBundle,
	}
}

var setups = map[operatorv1.ProductVariant]Setup{}

// RegisterSetup installs s as the setup for the given variant. Registration
// replaces any prior setup, so it is safe to call more than once. Variants
// without a registered setup get the base render context.
func RegisterSetup(variant operatorv1.ProductVariant, s Setup) {
	setups[variant] = s
}

// RunSetup runs the setup registered for the installation variant and returns
// its RenderContext, or the base render context when the variant has no setup.
func RunSetup(in Inputs) (RenderContext, error) {
	if in.Installation != nil {
		if s, ok := setups[in.Installation.Variant]; ok {
			return s(in)
		}
	}
	return BaseRenderContext(in), nil
}
