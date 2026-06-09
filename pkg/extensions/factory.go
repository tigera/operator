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

// Inputs is the reconcile state a RenderContextBuilder builds a RenderContext
// from. The installation controller populates it directly. It carries both the
// values that flow straight into the RenderContext and the side-effecting
// dependencies (Client, CertificateManager) a builder needs to produce
// controller-side artifacts.
type Inputs struct {
	Ctx                context.Context
	Client             client.Client
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	CertificateManager certificatemanager.CertificateManager
	TrustedBundle      certificatemanagement.TrustedBundle
	ClusterDomain      string
}

// RenderContextBuilder builds the RenderContext handed to render modifiers. It
// performs any controller-side work (creating certificates, extending the
// trusted bundle) and returns the assembled RenderContext - or an error that
// aborts the reconcile.
//
// This is the generic seam controllers use to extend base operator behavior;
// its first consumer is Calico Enterprise, but nothing here is enterprise
// specific. A builder is registered per variant, so it only runs for its own
// variant and need not re-check it.
type RenderContextBuilder func(in Inputs) (RenderContext, error)

// BaseRenderContext maps the generically-gathered inputs onto a RenderContext.
// Every registered builder builds on it, so the base fields are assembled in
// exactly one place. A builder layers its side-effect artifacts (e.g.
// NodePrometheusTLS) on top of the returned value.
func BaseRenderContext(in Inputs) RenderContext {
	return RenderContext{
		Installation:       in.Installation,
		FelixConfiguration: in.FelixConfiguration,
		ClusterDomain:      in.ClusterDomain,
		TrustedBundle:      in.TrustedBundle,
	}
}

var renderContextBuilders = map[operatorv1.ProductVariant]RenderContextBuilder{}

// RegisterRenderContextBuilder installs f as the builder for the given variant.
// Registration replaces any prior builder, so it is safe to call more than
// once. Variants without a registered builder get the base render context.
func RegisterRenderContextBuilder(variant operatorv1.ProductVariant, f RenderContextBuilder) {
	renderContextBuilders[variant] = f
}

// BuildRenderContext builds the RenderContext from in using the builder
// registered for the installation variant, or the base render context when the
// variant has no registered builder.
func BuildRenderContext(in Inputs) (RenderContext, error) {
	if in.Installation != nil {
		if f, ok := renderContextBuilders[in.Installation.Variant]; ok {
			return f(in)
		}
	}
	return BaseRenderContext(in), nil
}
