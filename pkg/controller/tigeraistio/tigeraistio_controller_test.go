// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package tigeraistio

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("tigeraistio controller tests", func() {

	var c client.Client
	var ctx context.Context
	var scheme *runtime.Scheme

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
	})

	It("should set IstioStatus to Deploying and Ready after reconciliation", func() {
		cr := &operatorv1.TigeraIstio{}
		cr.Name = "default"
		Expect(c.Create(ctx, cr)).To(Succeed())

		r := &ReconcileTigeraIstio{
			Client: c,
			scheme: scheme,
			status: status.New(c, "tigeraistio", &common.VersionInfo{Major: 1, Minor: 25}),
		}

		req := reconcile.Request{NamespacedName: client.ObjectKey{Name: "default"}}
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		updated := &operatorv1.TigeraIstio{}
		Expect(c.Get(ctx, client.ObjectKey{Name: "default"}, updated)).To(Succeed())
		Expect(updated.Status.IstioStatus == "Deploying" || updated.Status.IstioStatus == "Ready").To(BeTrue())
	})

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
	})

	It("should handle missing TigeraIstio CR", func() {
		_, msg, err := GetTigeraIstio(ctx, c)
		Expect(err).To(HaveOccurred())
		Expect(msg).To(ContainSubstring("failed to get TigeraIstio"))
	})

	It("should set IstioStatus to Deploying and Ready after reconciliation", func() {
		cr := &operatorv1.TigeraIstio{}
		cr.Name = "default"
		Expect(c.Create(ctx, cr)).To(Succeed())

		r := &ReconcileTigeraIstio{
			Client: c,
			scheme: scheme,
			status: status.New(c, "tigeraistio", &common.VersionInfo{Major: 1, Minor: 25}),
		}

		req := reconcile.Request{NamespacedName: client.ObjectKey{Name: "default"}}
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		updated := &operatorv1.TigeraIstio{}
		Expect(c.Get(ctx, client.ObjectKey{Name: "default"}, updated)).To(Succeed())
		Expect(updated.Status.IstioStatus == "Deploying" || updated.Status.IstioStatus == "Ready").To(BeTrue())
	})

	It("should find TigeraIstio CR if present", func() {
		// Create a default TigeraIstio CR
		cr := &operatorv1.TigeraIstio{}
		cr.Name = "default"
		Expect(c.Create(ctx, cr)).To(Succeed())
		found, msg, err := GetTigeraIstio(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg).To(BeEmpty())
		Expect(found.Name).To(Equal("default"))
	})

	It("should error on duplicate TigeraIstio CRs", func() {
		// Create both default and legacy CRs
		cr := &operatorv1.TigeraIstio{}
		cr.Name = "default"
		Expect(c.Create(ctx, cr)).To(Succeed())
		legacy := &operatorv1.TigeraIstio{}
		legacy.Name = "tigera-secure"
		Expect(c.Create(ctx, legacy)).To(Succeed())
		_, msg, err := GetTigeraIstio(ctx, c)
		Expect(err).To(HaveOccurred())
		Expect(msg).To(Equal("Duplicate configuration detected"))
	})
})
