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

package podiprecovery

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

const ns = "calico-system"

var _ = Describe("PodIPRecovery controller", func() {
	var (
		ctx context.Context
		c   client.Client
		r   *Reconciler
	)

	newNode := func(name string, internalIPs ...string) *corev1.Node {
		n := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}
		for _, ip := range internalIPs {
			n.Status.Addresses = append(n.Status.Addresses, corev1.NodeAddress{
				Type:    corev1.NodeInternalIP,
				Address: ip,
			})
		}
		return n
	}

	newPod := func(name, nodeName, podIP string, hostNetwork bool, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels:    labels,
			},
			Spec: corev1.PodSpec{
				NodeName:    nodeName,
				HostNetwork: hostNetwork,
			},
			Status: corev1.PodStatus{
				PodIP:  podIP,
				PodIPs: []corev1.PodIP{{IP: podIP}},
			},
		}
	}

	BeforeEach(func() {
		ctx = context.Background()
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		r = &Reconciler{client: c, scheme: scheme}
	})

	reconcileNode := func(nodeName string) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
		Expect(err).NotTo(HaveOccurred())
	}

	podExists := func(name string) bool {
		err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &corev1.Pod{})
		if apierrors.IsNotFound(err) {
			return false
		}
		Expect(err).NotTo(HaveOccurred())
		return true
	}

	Context("Reconcile", func() {
		It("leaves a pod alone when its IP matches the node InternalIP", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.1"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-typha"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeTrue())
		})

		It("deletes a hostNetwork pod whose IP doesn't match the node InternalIP", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-typha"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeFalse())
		})

		It("deletes stale pods of multiple workloads on the same node in one reconcile (no pacing)", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha-1", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-typha"}))).To(Succeed())
			Expect(c.Create(ctx, newPod("node-1", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-node"}))).To(Succeed())
			Expect(c.Create(ctx, newPod("nodewin-1", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-node-windows"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha-1")).To(BeFalse())
			Expect(podExists("node-1")).To(BeFalse())
			Expect(podExists("nodewin-1")).To(BeFalse())
		})

		It("only touches pods on the reconciled node", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newNode("node2", "10.0.0.3"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha-1", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-typha"}))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha-2", "node2", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-typha"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha-1")).To(BeFalse(), "stale pod on node1 should be deleted")
			Expect(podExists("typha-2")).To(BeTrue(), "stale pod on node2 should be untouched")
		})

		It("returns without error when the node is gone", func() {
			// No node created; reconcile should be a no-op.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "missing"}})
			Expect(err).NotTo(HaveOccurred())
		})

		It("skips a non-hostNetwork pod even if its labels match", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("cnipod", "node1", "10.244.0.5", false,
				map[string]string{"k8s-app": "calico-typha"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("cnipod")).To(BeTrue())
		})

		It("matches dual-stack pod IPs against any of the node's InternalIPs", func() {
			node := newNode("node1", "10.0.0.1", "fd00::1")
			Expect(c.Create(ctx, node)).To(Succeed())

			// Pod reports both v4 and v6; one matches, so the pod is healthy.
			pod := newPod("typha", "node1", "10.0.0.1", true, map[string]string{"k8s-app": "calico-typha"})
			pod.Status.PodIPs = []corev1.PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}}
			Expect(c.Create(ctx, pod)).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeTrue())
		})

		It("skips reconcile when the node has no InternalIPs reported", func() {
			// Avoid deleting based on a transient empty status.
			Expect(c.Create(ctx, newNode("node1" /* no IPs */))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "calico-typha"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeTrue())
		})

		It("deletes stale apiserver pods (different label scheme)", func() {
			// apiserver uses {apiserver: true} rather than k8s-app=...
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("apiserver", "node1", "10.0.0.1", true,
				map[string]string{"apiserver": "true"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("apiserver")).To(BeFalse())
		})

		It("leaves a pending pod (no podIPs reported yet) alone", func() {
			// A pod that was just scheduled but hasn't been admitted by the
			// kubelet yet has empty status.podIPs. Deleting it would race the
			// kubelet, which is about to populate the IPs correctly from the
			// node's current address.
			Expect(c.Create(ctx, newNode("node1", "10.0.0.1"))).To(Succeed())
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: ns,
					Labels: map[string]string{"k8s-app": "calico-typha"}},
				Spec: corev1.PodSpec{NodeName: "node1", HostNetwork: true},
				// Intentionally no Status.PodIPs / Status.PodIP — pending pod.
			}
			Expect(c.Create(ctx, pod)).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("pending")).To(BeTrue())
		})
	})

	Context("internalIPChangedPredicate", func() {
		pred := internalIPChangedPredicate()

		It("enqueues on Create", func() {
			Expect(pred.Create(event.CreateEvent{Object: newNode("n1", "10.0.0.1")})).To(BeTrue())
		})

		It("does not enqueue on Delete", func() {
			Expect(pred.Delete(event.DeleteEvent{Object: newNode("n1", "10.0.0.1")})).To(BeFalse())
		})

		It("enqueues on Update when InternalIPs change", func() {
			old := newNode("n1", "10.0.0.1")
			new := newNode("n1", "10.0.0.2")
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeTrue())
		})

		It("does not enqueue on Update when InternalIPs are unchanged (heartbeat-only)", func() {
			old := newNode("n1", "10.0.0.1")
			new := newNode("n1", "10.0.0.1")
			// Simulate a heartbeat that adds a Hostname address but keeps the InternalIP.
			new.Status.Addresses = append(new.Status.Addresses, corev1.NodeAddress{
				Type:    corev1.NodeHostName,
				Address: "n1",
			})
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})

		It("treats InternalIPs as a set (order-insensitive)", func() {
			old := newNode("n1", "10.0.0.1", "fd00::1")
			new := newNode("n1", "fd00::1", "10.0.0.1")
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})

		It("enqueues when a new InternalIP is added", func() {
			old := newNode("n1", "10.0.0.1")
			new := newNode("n1", "10.0.0.1", "fd00::1")
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeTrue())
		})

		It("does not enqueue on Update when only ExternalIP changes", func() {
			// Cloud environments commonly reassign external IPs while the
			// node's internal IP stays put. Don't react to those.
			old := newNode("n1", "10.0.0.1")
			old.Status.Addresses = append(old.Status.Addresses, corev1.NodeAddress{
				Type: corev1.NodeExternalIP, Address: "203.0.113.1",
			})
			new := newNode("n1", "10.0.0.1")
			new.Status.Addresses = append(new.Status.Addresses, corev1.NodeAddress{
				Type: corev1.NodeExternalIP, Address: "203.0.113.99",
			})
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})
	})
})
