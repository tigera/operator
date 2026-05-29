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
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/operator"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ = Describe("installation enterprise extension", func() {
	BeforeEach(func() { enterprise.Register() })
	AfterEach(func() {
		operator.ResetForTest()
		operator.ResetExtensionsForTest()
	})

	It("rejects a zero prometheus reporter port", func() {
		port := 0
		p := newPrep(operatorv1.TigeraSecureEnterprise)
		p.FelixConfiguration = &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{PrometheusReporterPort: &port}}
		_, err := operator.GetInstallationExtension().Prepare(p)
		Expect(err).To(HaveOccurred())
	})

	It("creates the node prometheus keypair for the enterprise variant", func() {
		p := newPrep(operatorv1.TigeraSecureEnterprise)
		p.FelixConfiguration = &v3.FelixConfiguration{}
		ctx, err := operator.GetInstallationExtension().Prepare(p)
		Expect(err).NotTo(HaveOccurred())
		Expect(ctx.NodePrometheusTLS).NotTo(BeNil())
	})

	It("is a no-op for the Calico variant", func() {
		p := newPrep(operatorv1.Calico)
		ctx, err := operator.GetInstallationExtension().Prepare(p)
		Expect(err).NotTo(HaveOccurred())
		Expect(ctx.NodePrometheusTLS).To(BeNil())
	})
})

func newPrep(variant operatorv1.ProductVariant) operator.InstallationPrep {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())
	trustedBundle := certManager.CreateTrustedBundle()

	return operator.InstallationPrep{
		Ctx:    context.Background(),
		Client: c,
		Installation: &operatorv1.InstallationSpec{
			Variant: variant,
		},
		FelixConfiguration: &v3.FelixConfiguration{},
		CertificateManager: certManager,
		TrustedBundle:      trustedBundle,
		ClusterDomain:      "cluster.local",
	}
}
