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

package uigateway_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/uigateway"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	rgateway "github.com/tigera/operator/pkg/render/gateway"
)

var _ = Describe("UnhealthyReason", func() {
	const ns = "calico-system"

	var (
		ctx context.Context
		h   *uigateway.Config
	)

	cond := func(t string, status metav1.ConditionStatus, msg string) metav1.Condition {
		return metav1.Condition{Type: t, Status: status, Message: msg, Reason: "Test", LastTransitionTime: metav1.Now()}
	}

	newGateway := func(conds ...metav1.Condition) *gapi.Gateway {
		return &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-manager-gateway", Namespace: ns},
			Status:     gapi.GatewayStatus{Conditions: conds},
		}
	}

	newRoute := func(conds ...metav1.Condition) *gapi.HTTPRoute {
		route := &gapi.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-manager-route", Namespace: ns},
		}
		if len(conds) > 0 {
			route.Status.Parents = []gapi.RouteParentStatus{{Conditions: conds}}
		}
		return route
	}

	healthyGateway := func() *gapi.Gateway {
		return newGateway(
			cond(string(gapi.GatewayConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.GatewayConditionProgrammed), metav1.ConditionTrue, ""),
		)
	}

	build := func(objs ...client.Object) {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(objs...).Build()
		h = &uigateway.Config{Client: cli, ResourcePrefix: "calico-manager"}
	}

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("reports a missing Gateway", func() {
		build()
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("not found yet"))
	})

	It("reports Gateway not accepted", func() {
		build(newGateway(cond(string(gapi.GatewayConditionAccepted), metav1.ConditionFalse, "invalid listener")))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("Gateway not accepted: invalid listener"))
	})

	It("reports Gateway not programmed", func() {
		build(newGateway(
			cond(string(gapi.GatewayConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.GatewayConditionProgrammed), metav1.ConditionFalse, "no addresses assigned"),
		))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("Gateway not programmed: no addresses assigned"))
	})

	It("treats missing Gateway conditions as healthy and moves on to the HTTPRoute", func() {
		build(newGateway(), newRoute())
		Expect(h.UnhealthyReason(ctx, ns)).To(BeEmpty())
	})

	It("reports a missing HTTPRoute once the Gateway is healthy", func() {
		build(healthyGateway())
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("HTTPRoute"))
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("not found yet"))
	})

	It("reports HTTPRoute not accepted", func() {
		build(healthyGateway(), newRoute(cond(string(gapi.RouteConditionAccepted), metav1.ConditionFalse, "no matching parent")))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("HTTPRoute not accepted: no matching parent"))
	})

	It("reports HTTPRoute refs not resolved", func() {
		build(healthyGateway(), newRoute(
			cond(string(gapi.RouteConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.RouteConditionResolvedRefs), metav1.ConditionFalse, "backend not permitted"),
		))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("HTTPRoute refs not resolved: backend not permitted"))
	})

	It("returns empty when the Gateway and HTTPRoute are healthy", func() {
		build(healthyGateway(), newRoute(
			cond(string(gapi.RouteConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.RouteConditionResolvedRefs), metav1.ConditionTrue, ""),
		))
		Expect(h.UnhealthyReason(ctx, ns)).To(BeEmpty())
	})
})

var _ = Describe("Cleanup helpers", func() {
	const (
		prefix    = "calico-whisker"
		backendNS = "calico-system"
	)

	var (
		ctx context.Context
		cli client.Client
		h   *uigateway.Config
	)

	labeledGateway := func(name, ns string) *gapi.Gateway {
		return &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{rgateway.GatewayLabel: prefix},
		}}
	}

	build := func(objs ...client.Object) {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(objs...).Build()
		h = &uigateway.Config{
			Client:           cli,
			ResourcePrefix:   prefix,
			TLSSecretName:    prefix + "-gateway-tls",
			BackendNamespace: backendNS,
		}
	}

	// deletionNamespaces collects, per object type, the namespaces the given
	// components mark for deletion.
	deletionNamespaces := func(components []render.Component) (gateways, backends []string) {
		for _, c := range components {
			_, toDelete := c.Objects()
			for _, obj := range toDelete {
				switch obj.(type) {
				case *gapi.Gateway:
					gateways = append(gateways, obj.GetNamespace())
				case *envoyapi.Backend:
					backends = append(backends, obj.GetNamespace())
				}
			}
		}
		return
	}

	BeforeEach(func() {
		ctx = context.Background()
	})

	Describe("Namespaces", func() {
		It("returns sorted, de-duplicated namespaces of labeled Gateways", func() {
			build(
				labeledGateway("gw-1", "ns-b"),
				labeledGateway("gw-2", "ns-a"),
				labeledGateway("gw-3", "ns-a"),
			)
			namespaces, crdsPresent, err := h.Namespaces(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(crdsPresent).To(BeTrue())
			Expect(namespaces).To(Equal([]string{"ns-a", "ns-b"}))
		})

		It("ignores Gateways carrying another component's label or no label", func() {
			other := labeledGateway("gw-other", "ns-c")
			other.Labels[rgateway.GatewayLabel] = "calico-manager"
			unlabeled := &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw-user", Namespace: "ns-d"}}
			build(labeledGateway("gw-1", "ns-a"), other, unlabeled)

			namespaces, crdsPresent, err := h.Namespaces(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(crdsPresent).To(BeTrue())
			Expect(namespaces).To(Equal([]string{"ns-a"}))
		})

		It("reports the gateway CRDs absent on NoKindMatchError", func() {
			build()
			h.Client = noGatewayKindClient{cli}
			namespaces, crdsPresent, err := h.Namespaces(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(crdsPresent).To(BeFalse())
			Expect(namespaces).To(BeEmpty())
		})
	})

	Describe("MoveCleanup", func() {
		It("returns deletion components only for namespaces outside the desired one", func() {
			build(
				labeledGateway(prefix+"-gateway", "ns-a"),
				labeledGateway(prefix+"-gateway", backendNS),
			)
			components, err := h.MoveCleanup(ctx, backendNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(HaveLen(1))

			gateways, backends := deletionNamespaces(components)
			Expect(gateways).To(Equal([]string{"ns-a"}))
			// The Backend stays: it lives in the backend namespace and the new
			// render still routes to it.
			Expect(backends).To(BeEmpty())
		})

		It("returns nothing when every labeled Gateway is in the desired namespace", func() {
			build(labeledGateway(prefix+"-gateway", backendNS))
			components, err := h.MoveCleanup(ctx, backendNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(BeEmpty())
		})
	})

	Describe("Teardown", func() {
		It("tears down every labeled Gateway's namespace plus the backend namespace", func() {
			build(labeledGateway(prefix+"-gateway", "ns-a"))
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())

			gateways, backends := deletionNamespaces(components)
			Expect(gateways).To(ConsistOf("ns-a", backendNS))
			Expect(backends).To(ConsistOf(backendNS, backendNS))
		})

		It("deletes nothing when no labeled Gateway exists", func() {
			build()
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(BeEmpty(),
				"the Gateway is rendered first, so without one nothing of ours is on the cluster and the Backend's kind may not even be served")
		})

		It("returns nothing when the gateway CRDs are absent", func() {
			build()
			h.Client = noGatewayKindClient{cli}
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(BeEmpty())
		})
	})

	Describe("EnsureNamespace", func() {
		It("creates the namespace when it does not exist", func() {
			build()
			Expect(uigateway.EnsureNamespace(ctx, cli, "ns-a")).NotTo(HaveOccurred())

			ns := &corev1.Namespace{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "ns-a"}, ns)).NotTo(HaveOccurred())
			Expect(ns.Labels).To(HaveKeyWithValue("name", "ns-a"))
			Expect(ns.OwnerReferences).To(BeEmpty())
		})

		It("leaves an existing namespace untouched", func() {
			build(&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "ns-a",
					Labels: map[string]string{"team": "netsec"},
				},
			})
			Expect(uigateway.EnsureNamespace(ctx, cli, "ns-a")).NotTo(HaveOccurred())

			ns := &corev1.Namespace{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "ns-a"}, ns)).NotTo(HaveOccurred())
			Expect(ns.Labels).To(Equal(map[string]string{"team": "netsec"}))
		})
	})
})

// noGatewayKindClient simulates a cluster without the Gateway API CRDs: listing
// Gateways fails with NoKindMatchError, everything else passes through.
type noGatewayKindClient struct {
	client.Client
}

func (c noGatewayKindClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*gapi.GatewayList); ok {
		return &apimeta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "gateway.networking.k8s.io", Kind: "Gateway"}}
	}
	return c.Client.List(ctx, list, opts...)
}
