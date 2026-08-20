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

package sharedconfig_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/sharedconfig"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("policySyncPathPrefix", func() {
	var c client.Client
	var ctx context.Context
	var w sharedconfig.Writer

	apply := func() string {
		fc, err := w.ApplyFelixConfiguration(ctx, sharedconfig.DeclarePolicySyncPathPrefix(ctx, c))
		Expect(err).NotTo(HaveOccurred())
		return fc.Spec.PolicySyncPathPrefix
	}

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		w = sharedconfig.NewWriter(c, false)
	})

	It("should stay unset when no feature needs it", func() {
		Expect(apply()).To(BeEmpty())
	})

	It("should be set while an egress gateway exists", func() {
		Expect(c.Create(ctx, &operatorv1.EgressGateway{
			ObjectMeta: metav1.ObjectMeta{Name: "egw", Namespace: "default"},
		})).NotTo(HaveOccurred())
		Expect(apply()).To(Equal("/var/run/nodeagent"))
	})

	It("should be set while the GatewayAPI CR exists", func() {
		Expect(c.Create(ctx, &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).NotTo(HaveOccurred())
		Expect(apply()).To(Equal("/var/run/nodeagent"))
	})

	It("should be set while the application layer needs it", func() {
		enabled := operatorv1.ApplicationLayerPolicyEnabled
		Expect(c.Create(ctx, &operatorv1.ApplicationLayer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.ApplicationLayerSpec{ApplicationLayerPolicy: &enabled},
		})).NotTo(HaveOccurred())
		Expect(apply()).To(Equal("/var/run/nodeagent"))
	})

	It("should be set while Istio needs it on Enterprise", func() {
		Expect(c.Create(ctx, &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.Istio{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).NotTo(HaveOccurred())
		Expect(apply()).To(Equal("/var/run/nodeagent"))
	})

	It("should stay unset while Istio is the only consumer on Calico", func() {
		Expect(c.Create(ctx, &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operatorv1.InstallationSpec{Variant: operatorv1.Calico},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.Istio{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).NotTo(HaveOccurred())
		Expect(apply()).To(BeEmpty())
	})

	It("should be cleared when the last consumer goes away", func() {
		gw := &operatorv1.GatewayAPI{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
		Expect(c.Create(ctx, gw)).NotTo(HaveOccurred())
		Expect(apply()).To(Equal("/var/run/nodeagent"))

		Expect(c.Delete(ctx, gw)).NotTo(HaveOccurred())
		Expect(apply()).To(BeEmpty())
	})

	It("should keep a user's own path", func() {
		Expect(c.Create(ctx, &v3.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/customer"},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).NotTo(HaveOccurred())
		Expect(apply()).To(Equal("/var/run/customer"))
	})
})
