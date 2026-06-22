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
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
)

var _ = Describe("installation controller extension", func() {
	It("rejects a zero prometheus reporter port", func() {
		port := 0
		cc := newControllerContext(operatorv1.CalicoEnterprise)
		cc.FelixConfiguration = &v3.FelixConfiguration{
			Spec: v3.FelixConfigurationSpec{PrometheusReporterPort: &port},
		}
		Expect(ext.Validate(cc)).To(HaveOccurred())
	})

	DescribeTable("defaults dnsTrustedServers for providers whose DNS service isn't kube-dns",
		func(provider operatorv1.Provider, expected []string) {
			fc := &v3.FelixConfiguration{}
			install := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise, KubernetesProvider: provider}
			updated, err := ext.DefaultFelixConfiguration(extensions.InstallationController, install, fc)
			Expect(err).NotTo(HaveOccurred())
			if expected == nil {
				Expect(updated).To(BeFalse())
				Expect(fc.Spec.DNSTrustedServers).To(BeNil())
				return
			}
			Expect(updated).To(BeTrue())
			Expect(*fc.Spec.DNSTrustedServers).To(ConsistOf(expected))
		},
		Entry("OpenShift", operatorv1.ProviderOpenShift, []string{"k8s-service:openshift-dns/dns-default"}),
		Entry("RKE2", operatorv1.ProviderRKE2, []string{"k8s-service:kube-system/rke2-coredns-rke2-coredns"}),
		Entry("other providers keep the felix default", operatorv1.ProviderNone, nil),
	)

	It("does no felix defaulting for the Calico variant", func() {
		fc := &v3.FelixConfiguration{}
		updated, err := ext.DefaultFelixConfiguration(extensions.InstallationController, &operatorv1.InstallationSpec{Variant: operatorv1.Calico, KubernetesProvider: operatorv1.ProviderOpenShift}, fc)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse())
		Expect(fc.Spec.DNSTrustedServers).To(BeNil())
	})

	It("manages the node prometheus and kube-controllers metrics keypairs for the enterprise variant", func() {
		_, managed, err := ext.ExtendContext(newControllerContext(operatorv1.CalicoEnterprise))
		Expect(err).NotTo(HaveOccurred())
		names := []string{}
		for _, kp := range managed {
			names = append(names, kp.GetName())
		}
		Expect(names).To(ConsistOf(render.NodePrometheusTLSServerSecret, kubecontrollers.KubeControllerPrometheusTLSSecret))
	})

	It("is a no-op for the Calico variant", func() {
		_, managed, err := ext.ExtendContext(newControllerContext(operatorv1.Calico))
		Expect(err).NotTo(HaveOccurred())
		Expect(managed).To(BeEmpty())
	})
})

func newControllerContext(variant operatorv1.ProductVariant) extensions.ControllerContext {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())
	trustedBundle := certManager.CreateTrustedBundle()

	return extensions.ControllerContext{
		RenderContext: extensions.RenderContext{
			Installation:       &operatorv1.InstallationSpec{Variant: variant},
			FelixConfiguration: &v3.FelixConfiguration{},
			TrustedBundle:      trustedBundle,
			ClusterDomain:      "cluster.local",
		},
		Controller:         extensions.InstallationController,
		Ctx:                context.Background(),
		Client:             c,
		CertificateManager: certManager,
	}
}
