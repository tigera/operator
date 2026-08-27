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
	"fmt"

	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common/discovery"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/enterprise/apiserver"
	"github.com/tigera/operator/pkg/enterprise/clusterconnection"
	"github.com/tigera/operator/pkg/enterprise/csr"
	"github.com/tigera/operator/pkg/enterprise/gatewayapi"
	"github.com/tigera/operator/pkg/enterprise/goldmane"
	"github.com/tigera/operator/pkg/enterprise/installation"
	"github.com/tigera/operator/pkg/enterprise/istio"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/enterprise/tiers"
	"github.com/tigera/operator/pkg/enterprise/whisker"
	"github.com/tigera/operator/pkg/enterprise/windows"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/version"
)

// Build returns the Calico Enterprise extensions, and is called once the variant is
// resolved. Tenancy and the cloud build flag are resolved here rather than passed in,
// since each only ever describes an Enterprise install.
func Build(ctx context.Context, variant operatorv1.ProductVariant, clientset kubernetes.Interface, manageCRDs, useV3CRDs bool) (extensions.Extensions, error) {
	o := eoptions.Options{
		ManageCRDs: manageCRDs,
		UseV3CRDs:  useV3CRDs,
		Cloud:      isCloudBuild(),
	}

	if variant.IsEnterprise() {
		// Tenancy shows up as a namespaced Manager, a CRD only Enterprise installs.
		multiTenant, err := discovery.MultiTenant(ctx, clientset)
		if err != nil {
			return extensions.Extensions{}, fmt.Errorf("failed to determine the tenancy mode: %w", err)
		}
		o.MultiTenant = multiTenant
	}

	return New(variant, o), nil
}

// New builds the Calico Enterprise extensions from options already resolved.
func New(variant operatorv1.ProductVariant, o eoptions.Options) extensions.Extensions {
	// Startup is registered whatever the variant, since the namespaces Enterprise
	// manages are off limits to a Calico install too.
	set := extensions.Set{Startup: startup{variant: variant, opts: o}}

	// Enterprise has two spellings, so match on the product rather than the constant:
	// an Installation asking for the deprecated TigeraSecureEnterprise still gets the
	// Enterprise extensions.
	switch {
	case variant.IsEnterprise():
		set.Installation = installation.New(variant, o)
		set.Windows = windows.New(variant)
		set.APIServer = apiserver.New(variant, o)
		set.ClusterConnection = clusterconnection.New(variant)
		set.Tiers = tiers.New(o)
		set.CSR = csr.New()
		set.Istio = istio.New(variant)
		set.Goldmane = goldmane.New(variant)
		set.Whisker = whisker.New(variant)
		set.GatewayAPI = gatewayapi.New(variant)
		set.Images = images(variant, o)
	case variant == operatorv1.Calico:
		// Clean up what a prior Enterprise installation left behind.
		set.APIServer = apiserver.CalicoCleanup{}
	}

	return extensions.New(set)
}

// isCloudBuild reports whether the binary was built for Calico Cloud. The Makefile bakes
// the answer in through CLOUD_LDFLAGS so it cannot be flipped at runtime.
func isCloudBuild() bool {
	return version.BuildVariant == "cloud"
}

// images is every component whose image differs for Enterprise.
func images(variant operatorv1.ProductVariant, o eoptions.Options) *imageoverride.Overrides {
	set := imageoverride.New()
	set.Register(variant, render.ComponentNameCalico, components.ComponentTigeraCalico)
	installation.RegisterImages(set, variant, o)
	windows.RegisterImages(set, variant)
	gatewayapi.RegisterImages(set, variant)
	istio.RegisterImages(set, variant)
	return set
}
