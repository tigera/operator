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

package istio

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("istio controller tests", func() {
	var c client.Client
	var ctx context.Context
	var scheme *runtime.Scheme
	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
	})

	It("should set condition to Progressing when resources are not ready, and Ready when all are ready", func() {
		inst := &operatorv1.Installation{}
		inst.Name = "default"
		Expect(c.Create(ctx, inst)).To(Succeed())
		cr := &operatorv1.Istio{}
		cr.Name = "default"
		Expect(c.Create(ctx, cr)).To(Succeed())

		// Create Istiod deployment (not ready)
		istiodDep := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-istiod",
				Namespace: "calico-istio",
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
			},
			Status: appsv1.DeploymentStatus{
				ReadyReplicas: 0, // Not ready
			},
		}
		Expect(c.Create(ctx, istiodDep)).To(Succeed())

		// Create CNI DaemonSet (not ready)
		cniDs := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-istio-cni",
				Namespace: "calico-istio",
			},
			Status: appsv1.DaemonSetStatus{
				NumberReady:            0,
				DesiredNumberScheduled: 1,
			},
		}
		Expect(c.Create(ctx, cniDs)).To(Succeed())

		// Create ZTunnel DaemonSet (not ready)
		ztunnelDs := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-istio-ztunnel",
				Namespace: "calico-istio",
			},
			Status: appsv1.DaemonSetStatus{
				NumberReady:            0,
				DesiredNumberScheduled: 1,
			},
		}
		Expect(c.Create(ctx, ztunnelDs)).To(Succeed())

		r := &ReconcileIstio{
			Client: c,
			scheme: scheme,
			status: status.New(c, "istio", &common.VersionInfo{Major: 1, Minor: 25}),
		}

		req := reconcile.Request{NamespacedName: client.ObjectKey{Name: "default"}}
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		updated := &operatorv1.Istio{}
		Expect(c.Get(ctx, client.ObjectKey{Name: "default"}, updated)).To(Succeed())
		Expect(updated.Status.Conditions).To(HaveLen(1))
		Expect(updated.Status.Conditions[0].Type).To(Equal("Progressing"))
		Expect(updated.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))

		// Now mark all resources as ready
		istiodDep.Status.ReadyReplicas = 1
		Expect(c.Status().Update(ctx, istiodDep)).To(Succeed())
		cniDs.Status.NumberReady = 1
		Expect(c.Status().Update(ctx, cniDs)).To(Succeed())
		ztunnelDs.Status.NumberReady = 1
		Expect(c.Status().Update(ctx, ztunnelDs)).To(Succeed())

		// Reconcile again
		_, err = r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "default"}, updated)).To(Succeed())
		Expect(updated.Status.Conditions).To(HaveLen(2))
		Expect(updated.Status.Conditions[0].Type).To(Equal("Progressing"))
		Expect(updated.Status.Conditions[0].Status).To(Equal(metav1.ConditionFalse))
		Expect(updated.Status.Conditions[1].Type).To(Equal("Ready"))
		Expect(updated.Status.Conditions[1].Status).To(Equal(metav1.ConditionTrue))
	})

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
	})

	It("should handle missing Istio CR", func() {
		_, msg, err := GetIstio(ctx, c)
		Expect(err).To(HaveOccurred())
		Expect(msg).To(ContainSubstring("failed to get Istio"))
	})

	It("should find Istio CR if present", func() {
		// Create a default Istio CR
		cr := &operatorv1.Istio{}
		cr.Name = "default"
		Expect(c.Create(ctx, cr)).To(Succeed())
		found, msg, err := GetIstio(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg).To(BeEmpty())
		Expect(found.Name).To(Equal("default"))
	})

	It("should error on duplicate Istio CRs", func() {
		// Create both default and legacy CRs
		cr := &operatorv1.Istio{}
		cr.Name = "default"
		Expect(c.Create(ctx, cr)).To(Succeed())
		legacy := &operatorv1.Istio{}
		legacy.Name = "tigera-secure"
		Expect(c.Create(ctx, legacy)).To(Succeed())
		_, msg, err := GetIstio(ctx, c)
		Expect(err).To(HaveOccurred())
		Expect(msg).To(Equal("Duplicate configuration detected"))
	})
})
