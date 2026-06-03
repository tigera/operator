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

// Inputs is the reconcile state a RenderContextFactory builds a RenderContext
// from. The installation controller populates it through the With* options. It
// carries both the values that flow straight into the RenderContext and the
// side-effecting dependencies (Client, CertificateManager) a factory needs to
// produce controller-side artifacts.
type Inputs struct {
	Ctx                context.Context
	Client             client.Client
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	CertificateManager certificatemanager.CertificateManager
	TrustedBundle      certificatemanagement.TrustedBundle
	ClusterDomain      string
}

// RenderContextOption sets a field on the Inputs a factory builds from.
type RenderContextOption func(*Inputs)

func WithContext(ctx context.Context) RenderContextOption {
	return func(in *Inputs) { in.Ctx = ctx }
}

func WithClient(c client.Client) RenderContextOption {
	return func(in *Inputs) { in.Client = c }
}

func WithInstallation(i *operatorv1.InstallationSpec) RenderContextOption {
	return func(in *Inputs) { in.Installation = i }
}

func WithFelixConfiguration(fc *v3.FelixConfiguration) RenderContextOption {
	return func(in *Inputs) { in.FelixConfiguration = fc }
}

func WithCertificateManager(cm certificatemanager.CertificateManager) RenderContextOption {
	return func(in *Inputs) { in.CertificateManager = cm }
}

func WithTrustedBundle(tb certificatemanagement.TrustedBundle) RenderContextOption {
	return func(in *Inputs) { in.TrustedBundle = tb }
}

func WithClusterDomain(d string) RenderContextOption {
	return func(in *Inputs) { in.ClusterDomain = d }
}

// RenderContextFactory builds the RenderContext handed to render modifiers. New
// applies the options, performs any controller-side work (creating
// certificates, extending the trusted bundle), and returns the assembled
// RenderContext - or an error that aborts the reconcile.
//
// This is the generic seam controllers use to extend base operator behavior;
// its first consumer is Calico Enterprise, but nothing here is enterprise
// specific. The core operator default does no side-effecting work.
type RenderContextFactory interface {
	New(opts ...RenderContextOption) (RenderContext, error)
}

// ApplyInputs returns the Inputs produced by applying opts. Factories use it to
// collect the option-supplied state before doing their work.
func ApplyInputs(opts ...RenderContextOption) Inputs {
	var in Inputs
	for _, o := range opts {
		o(&in)
	}
	return in
}

// BaseRenderContext maps the generically-gathered inputs onto a RenderContext.
// The default factory and every registered factory build on it, so the base
// fields are assembled in exactly one place. A factory layers its side-effect
// artifacts (e.g. NodePrometheusTLS) on top of the returned value.
func BaseRenderContext(in Inputs) RenderContext {
	return RenderContext{
		Installation:       in.Installation,
		FelixConfiguration: in.FelixConfiguration,
		ClusterDomain:      in.ClusterDomain,
		TrustedBundle:      in.TrustedBundle,
	}
}

// defaultFactory is the core operator's RenderContextFactory. It does no
// side-effecting work and returns just the base RenderContext.
type defaultFactory struct{}

func (defaultFactory) New(opts ...RenderContextOption) (RenderContext, error) {
	return BaseRenderContext(ApplyInputs(opts...)), nil
}

var renderContextFactory RenderContextFactory = defaultFactory{}

// RegisterRenderContextFactory installs f as the factory the installation
// controller uses. Registration replaces any prior factory, so it is safe to
// call more than once. Without a registered factory the core operator default
// applies.
func RegisterRenderContextFactory(f RenderContextFactory) { renderContextFactory = f }

// GetRenderContextFactory returns the registered factory, or the core operator
// default when none is registered.
func GetRenderContextFactory() RenderContextFactory { return renderContextFactory }
