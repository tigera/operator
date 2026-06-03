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

package enterprise_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/extensions"
)

var _ = Describe("installation render context factory", func() {
	BeforeEach(func() { enterprise.Register() })
	AfterEach(func() { extensions.ResetForTest() })

	It("rejects a zero prometheus reporter port", func() {
		port := 0
		opts := newOpts(operatorv1.CalicoEnterprise)
		opts = append(opts, extensions.WithFelixConfiguration(&v3.FelixConfiguration{
			Spec: v3.FelixConfigurationSpec{PrometheusReporterPort: &port},
		}))
		_, err := extensions.GetRenderContextFactory().New(opts...)
		Expect(err).To(HaveOccurred())
	})

	It("creates the node prometheus keypair for the enterprise variant", func() {
		rc, err := extensions.GetRenderContextFactory().New(newOpts(operatorv1.CalicoEnterprise)...)
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.NodePrometheusTLS).NotTo(BeNil())
	})

	It("is a no-op for the Calico variant", func() {
		rc, err := extensions.GetRenderContextFactory().New(newOpts(operatorv1.Calico)...)
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.NodePrometheusTLS).To(BeNil())
	})
})

func newOpts(variant operatorv1.ProductVariant) []extensions.RenderContextOption {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())
	trustedBundle := certManager.CreateTrustedBundle()

	return []extensions.RenderContextOption{
		extensions.WithContext(context.Background()),
		extensions.WithClient(c),
		extensions.WithInstallation(&operatorv1.InstallationSpec{Variant: variant}),
		extensions.WithFelixConfiguration(&v3.FelixConfiguration{}),
		extensions.WithCertificateManager(certManager),
		extensions.WithTrustedBundle(trustedBundle),
		extensions.WithClusterDomain("cluster.local"),
	}
}
