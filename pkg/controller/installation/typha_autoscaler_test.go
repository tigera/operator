// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/status"
	. "github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

var _ = Describe("Test typha autoscaler ", func() {
	var statusManager *status.MockStatus
	var c *kfake.Clientset
	var ctx context.Context
	var cancel context.CancelFunc
	var nlw, tlw cache.ListerWatcher
	var nodeIndexInformer cache.SharedIndexInformer

	BeforeEach(func() {
		statusManager = new(status.MockStatus)

		objs := []runtime.Object{
			&corev1.Namespace{
				TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name: "calico-system",
				},
			},
		}
		c = kfake.NewClientset(objs...)
		nlw = NewNodeListWatch(c)
		tlw = NewTyphaListWatch(c)

		// Create the indexer and informer used by the typhaAutoscaler
		nodeIndexInformer = cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

		ctx, cancel = context.WithCancel(context.Background())
		go nodeIndexInformer.Run(ctx.Done())
		for !nodeIndexInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}
	})

	AfterEach(func() {
		cancel()
	})

	It("should initialize an autoscaler", func() {
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager)
		ta.start(ctx)
	})

	It("should get the correct number of nodes", func() {
		n1 := CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		_ = CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux"}, nil)

		// Don't start the autoscaler - this test only exercises getNodeCounts(), which reads
		// from the nodeIndexInformer directly. Starting it would race with node creation,
		// since autoscaleReplicas() can fire before the informer has picked up the new nodes.
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager)

		Eventually(func() error {
			schedulableNodes, linuxNodes := ta.getNodeCounts()
			if schedulableNodes != 2 {
				return fmt.Errorf("Expected 2 schedulable nodes, got %d", schedulableNodes)
			}
			if linuxNodes != 2 {
				return fmt.Errorf("Expected 2 linux nodes, got %d", linuxNodes)
			}
			return nil
		}, 5*time.Second).ShouldNot(HaveOccurred())

		n1.Spec.Unschedulable = true
		_, err := c.CoreV1().Nodes().Update(ctx, n1, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() error {
			schedulableNodes, linuxNodes := ta.getNodeCounts()
			if schedulableNodes != 1 {
				return fmt.Errorf("Expected 2 schedulable nodes, got %d", schedulableNodes)
			}
			if linuxNodes != 1 {
				return fmt.Errorf("Expected 2 linux nodes, got %d", linuxNodes)
			}
			return nil
		}, 5*time.Second).ShouldNot(HaveOccurred())
	})

	It("should scale the Typha up and down in response to the number of schedulable nodes", func() {
		typhaMeta := metav1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "calico-system",
		}
		// Create a typha deployment
		var r int32 = 0
		typha := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: typhaMeta,
			Spec: appsv1.DeploymentSpec{
				Replicas: &r,
			},
		}
		_, err := c.AppsV1().Deployments("calico-system").Create(ctx, typha, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a few nodes
		CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux"}, nil)

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerOptionPeriod(10*time.Millisecond))
		ta.start(ctx)

		// For clusters smaller than 3 nodes we only expect 1 replica.
		verifyTyphaReplicas(c, 1)

		// For three and four node clusters, we expect 2.
		n3 := CreateNode(c, "node3", map[string]string{"kubernetes.io/os": "linux"}, nil)
		verifyTyphaReplicas(c, 2)
		CreateNode(c, "node4", map[string]string{"kubernetes.io/os": "linux"}, nil)
		verifyTyphaReplicas(c, 2)

		// For > 4 nodes, we expect redundancy with 3 replicas.
		CreateNode(c, "node5", map[string]string{"kubernetes.io/os": "linux"}, nil)
		verifyTyphaReplicas(c, 3)

		// Verify that making a node unschedulable updates replicas. Should bring us back
		// down to 4 node scale.
		n3.Spec.Unschedulable = true
		_, err = c.CoreV1().Nodes().Update(ctx, n3, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		verifyTyphaReplicas(c, 2)
	})

	It("should not ignore non-migrated nodes in its count", func() {
		typhaMeta := metav1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "calico-system",
		}

		// Create a typha deployment
		var r int32 = 0
		typha := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: typhaMeta,
			Spec: appsv1.DeploymentSpec{
				Replicas: &r,
			},
		}
		_, err := c.AppsV1().Deployments("calico-system").Create(ctx, typha, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create five nodes, one of which is not yet migrated
		CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node3", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node4", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node5", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "pre-operator"}, nil)

		Eventually(func() []any {
			return nodeIndexInformer.GetStore().List()
		}).Should(HaveLen(5))

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerOptionPeriod(10*time.Millisecond))
		ta.start(ctx)

		verifyTyphaReplicas(c, 3)
	})

	It("should ignore aks virtual nodes in its count", func() {
		typhaMeta := metav1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "calico-system",
		}
		// Create a typha deployment
		var r int32 = 0
		typha := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: typhaMeta,
			Spec: appsv1.DeploymentSpec{
				Replicas: &r,
			},
		}
		_, err := c.AppsV1().Deployments("calico-system").Create(ctx, typha, metav1.CreateOptions{})
		Expect(err).To(BeNil())

		// Create five nodes, one of which is a virtual-kubelet
		CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux"}, nil)
		CreateNode(c, "node3", map[string]string{"kubernetes.io/os": "linux"}, nil)
		CreateNode(c, "node4", map[string]string{"kubernetes.io/os": "linux"}, nil)
		CreateNode(c, "node5", map[string]string{"kubernetes.io/os": "linux", "kubernetes.azure.com/cluster": "foo", "type": "virtual-kubelet"}, nil)

		Eventually(func() []any {
			return nodeIndexInformer.GetStore().List()
		}).Should(HaveLen(5))

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerOptionPeriod(10*time.Millisecond))
		ta.start(ctx)

		// normally we'd expect to see three replicas for five nodes, but since one node is a virtual-kubelet,
		// we should still only expect two
		verifyTyphaReplicas(c, 2)
	})

	It("should be degraded if there's not enough linux nodes", func() {
		typhaMeta := metav1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "calico-system",
		}

		// Create a typha deployment
		var r int32 = 0
		typha := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: typhaMeta,
			Spec: appsv1.DeploymentSpec{
				Replicas: &r,
			},
		}
		_, err := c.AppsV1().Deployments("calico-system").Create(ctx, typha, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		statusManager.On("SetDegraded", operator.ResourceScalingError, "Failed to autoscale typha - not enough linux nodes to schedule typha pods on, require 3 and have 2", mock.Anything, mock.Anything)

		// Create a few nodes
		CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux"}, nil)
		CreateNode(c, "node3", map[string]string{"kubernetes.io/os": "windows"}, nil)
		CreateNode(c, "node4", map[string]string{"kubernetes.io/os": "windows"}, nil)
		CreateNode(c, "node5", map[string]string{"kubernetes.io/os": "windows"}, nil)

		Eventually(func() []any {
			return nodeIndexInformer.GetStore().List()
		}).Should(HaveLen(5))

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerOptionPeriod(10*time.Millisecond))
		ta.start(ctx)

		// This blocks until the first run is done.
		ta.isDegraded()

		statusManager.AssertExpectations(GinkgoT())
	})

	Context("stale pod IP detection", func() {
		var ta *typhaAutoscaler

		const (
			typhaSelector       = "k8s-app=calico-typha"
			calicoNodeSelector  = "k8s-app=calico-node"
			windowsNodeSelector = "k8s-app=calico-node-windows"
		)

		BeforeEach(func() {
			// The autoscaler may degrade if the first tick fires before nodes are
			// added by the test body (race against ta.start). We don't care about
			// scaling behavior in these tests; allow any SetDegraded call.
			statusManager.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe()
			ta = newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerOptionPeriod(10*time.Millisecond))
			ta.start(ctx)
		})

		createNodeWithIP := func(name, ip string) *corev1.Node {
			node := CreateNode(c, name, map[string]string{"kubernetes.io/os": "linux"}, nil)
			node.Status.Addresses = []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: ip},
			}
			var err error
			node, err = c.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
			Expect(err).To(BeNil())
			return node
		}

		createPodWithLabel := func(name, nodeName, podIP, k8sApp string) *corev1.Pod {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: "calico-system",
					Labels:    map[string]string{"k8s-app": k8sApp},
				},
				Spec: corev1.PodSpec{
					NodeName: nodeName,
				},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: podIP}},
				},
			}
			var err error
			pod, err = c.CoreV1().Pods("calico-system").Create(ctx, pod, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			// fake client doesn't persist status on Create; update it separately.
			pod.Status.PodIPs = []corev1.PodIP{{IP: podIP}}
			pod, err = c.CoreV1().Pods("calico-system").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
			Expect(err).To(BeNil())
			return pod
		}

		// waitForNodes blocks until the node informer has observed n schedulable nodes.
		waitForNodes := func(n int) {
			EventuallyWithOffset(1, func() int {
				all, _ := ta.getNodeCounts()
				return all
			}, 5*time.Second).Should(Equal(n))
		}

		listPods := func(labelSelector string) []corev1.Pod {
			pods, err := c.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			Expect(err).To(BeNil())
			return pods.Items
		}

		It("returns 0 and deletes nothing when all pod IPs match the node InternalIP", func() {
			createNodeWithIP("node1", "10.0.0.1")
			createPodWithLabel("typha-abc", "node1", "10.0.0.1", "calico-typha")
			waitForNodes(1)

			deleted := ta.deleteStaleHostNetworkPods("calico-typha", typhaSelector, 1)
			Expect(deleted).To(Equal(0))
			Expect(listPods(typhaSelector)).To(HaveLen(1))
		})

		It("returns 1 and deletes a Typha pod whose IP doesn't match the node InternalIP", func() {
			createNodeWithIP("node1", "10.0.0.2")
			createPodWithLabel("typha-abc", "node1", "10.0.0.1", "calico-typha")
			waitForNodes(1)

			deleted := ta.deleteStaleHostNetworkPods("calico-typha", typhaSelector, 1)
			Expect(deleted).To(Equal(1))
			Expect(listPods(typhaSelector)).To(HaveLen(0))
		})

		It("deletes a stale calico-node (Linux) pod", func() {
			createNodeWithIP("node1", "10.0.0.2")
			createPodWithLabel("calico-node-abc", "node1", "10.0.0.1", "calico-node")
			waitForNodes(1)

			deleted := ta.deleteStaleHostNetworkPods("calico-node", calicoNodeSelector, 1)
			Expect(deleted).To(Equal(1))
			Expect(listPods(calicoNodeSelector)).To(HaveLen(0))
		})

		It("deletes a stale calico-node-windows pod", func() {
			createNodeWithIP("node1", "10.0.0.2")
			createPodWithLabel("calico-node-windows-abc", "node1", "10.0.0.1", "calico-node-windows")
			waitForNodes(1)

			deleted := ta.deleteStaleHostNetworkPods("calico-node-windows", windowsNodeSelector, 1)
			Expect(deleted).To(Equal(1))
			Expect(listPods(windowsNodeSelector)).To(HaveLen(0))
		})

		It("respects maxBatch=1 (default): exactly one stale pod deleted per call", func() {
			createNodeWithIP("node1", "10.0.0.2")
			createNodeWithIP("node2", "10.0.0.4")
			createPodWithLabel("typha-abc", "node1", "10.0.0.1", "calico-typha")
			createPodWithLabel("typha-def", "node2", "10.0.0.3", "calico-typha")
			waitForNodes(2)

			Expect(ta.deleteStaleHostNetworkPods("calico-typha", typhaSelector, 1)).To(Equal(1))
			Expect(listPods(typhaSelector)).To(HaveLen(1))

			Expect(ta.deleteStaleHostNetworkPods("calico-typha", typhaSelector, 1)).To(Equal(1))
			Expect(listPods(typhaSelector)).To(HaveLen(0))
		})

		It("respects maxBatch=N (>1): up to N stale pods deleted per call", func() {
			for i := 0; i < 5; i++ {
				nodeName := fmt.Sprintf("node%d", i)
				createNodeWithIP(nodeName, fmt.Sprintf("10.0.0.%d", 100+i))
				createPodWithLabel(fmt.Sprintf("calico-node-%d", i), nodeName, fmt.Sprintf("10.0.0.%d", i+1), "calico-node")
			}
			waitForNodes(5)

			// maxBatch=3 → delete 3 of the 5 stale pods.
			Expect(ta.deleteStaleHostNetworkPods("calico-node", calicoNodeSelector, 3)).To(Equal(3))
			Expect(listPods(calicoNodeSelector)).To(HaveLen(2))

			// Next call cleans up the remaining 2.
			Expect(ta.deleteStaleHostNetworkPods("calico-node", calicoNodeSelector, 3)).To(Equal(2))
			Expect(listPods(calicoNodeSelector)).To(HaveLen(0))
		})

		It("treats maxBatch < 1 as 1 (minimum-progress fallback)", func() {
			createNodeWithIP("node1", "10.0.0.2")
			createPodWithLabel("typha-abc", "node1", "10.0.0.1", "calico-typha")
			waitForNodes(1)

			// maxBatch=0 should still delete one pod (minimum-progress fallback).
			Expect(ta.deleteStaleHostNetworkPods("calico-typha", typhaSelector, 0)).To(Equal(1))
			Expect(listPods(typhaSelector)).To(HaveLen(0))
		})

		It("does not delete a pod whose node is not in the informer cache", func() {
			createPodWithLabel("typha-abc", "unknown-node", "10.0.0.1", "calico-typha")

			deleted := ta.deleteStaleHostNetworkPods("calico-typha", typhaSelector, 1)
			Expect(deleted).To(Equal(0))
			Expect(listPods(typhaSelector)).To(HaveLen(1))
		})

		It("paces Linux and Windows DaemonSets independently of each other", func() {
			createNodeWithIP("node-linux", "10.0.0.2")
			createNodeWithIP("node-win", "10.0.1.2")
			createPodWithLabel("calico-node-abc", "node-linux", "10.0.0.1", "calico-node")
			createPodWithLabel("calico-node-windows-abc", "node-win", "10.0.1.1", "calico-node-windows")
			waitForNodes(2)

			// Both DaemonSets have a stale pod; each call deletes its own.
			Expect(ta.deleteStaleHostNetworkPods("calico-node", calicoNodeSelector, 1)).To(Equal(1))
			Expect(ta.deleteStaleHostNetworkPods("calico-node-windows", windowsNodeSelector, 1)).To(Equal(1))
			Expect(listPods(calicoNodeSelector)).To(HaveLen(0))
			Expect(listPods(windowsNodeSelector)).To(HaveLen(0))
		})
	})

	Context("maxUnavailable resolution", func() {
		var ta *typhaAutoscaler

		BeforeEach(func() {
			// Allow any degradation that may happen due to race with autoscaler ticks.
			statusManager.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe()
			ta = newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerOptionPeriod(10*time.Millisecond))
			ta.start(ctx)
		})

		It("returns 1 for Typha when the PDB does not exist", func() {
			Expect(ta.resolveTyphaMaxUnavailable()).To(Equal(1))
		})

		It("resolves an int Typha PDB maxUnavailable", func() {
			var replicas int32 = 5
			_, err := c.AppsV1().Deployments("calico-system").Create(ctx, &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
				Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			mu := intstr.FromInt(2)
			_, err = c.PolicyV1().PodDisruptionBudgets("calico-system").Create(ctx, &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
				Spec:       policyv1.PodDisruptionBudgetSpec{MaxUnavailable: &mu},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			Expect(ta.resolveTyphaMaxUnavailable()).To(Equal(2))
		})

		It("resolves a percentage Typha PDB maxUnavailable against replica count", func() {
			var replicas int32 = 10
			_, err := c.AppsV1().Deployments("calico-system").Create(ctx, &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
				Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			mu := intstr.FromString("25%")
			_, err = c.PolicyV1().PodDisruptionBudgets("calico-system").Create(ctx, &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
				Spec:       policyv1.PodDisruptionBudgetSpec{MaxUnavailable: &mu},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			// 25% of 10 = 3 (rounded up from 2.5).
			Expect(ta.resolveTyphaMaxUnavailable()).To(Equal(3))
		})

		It("returns 1 for Typha when maxUnavailable resolves to 0", func() {
			var replicas int32 = 5
			_, err := c.AppsV1().Deployments("calico-system").Create(ctx, &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
				Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			mu := intstr.FromInt(0)
			_, err = c.PolicyV1().PodDisruptionBudgets("calico-system").Create(ctx, &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
				Spec:       policyv1.PodDisruptionBudgetSpec{MaxUnavailable: &mu},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			Expect(ta.resolveTyphaMaxUnavailable()).To(Equal(1))
		})

		It("returns 1 for a DaemonSet without RollingUpdate", func() {
			_, err := c.AppsV1().DaemonSets("calico-system").Create(ctx, &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"},
				Spec: appsv1.DaemonSetSpec{
					UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType},
				},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			Expect(ta.resolveDaemonSetMaxUnavailable("calico-node")).To(Equal(1))
		})

		It("resolves an int DaemonSet maxUnavailable", func() {
			mu := intstr.FromInt(4)
			_, err := c.AppsV1().DaemonSets("calico-system").Create(ctx, &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"},
				Spec: appsv1.DaemonSetSpec{
					UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
						Type: appsv1.RollingUpdateDaemonSetStrategyType,
						RollingUpdate: &appsv1.RollingUpdateDaemonSet{
							MaxUnavailable: &mu,
						},
					},
				},
				Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 100},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			Expect(ta.resolveDaemonSetMaxUnavailable("calico-node")).To(Equal(4))
		})

		It("resolves a percentage DaemonSet maxUnavailable against desired pod count", func() {
			mu := intstr.FromString("10%")
			_, err := c.AppsV1().DaemonSets("calico-system").Create(ctx, &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"},
				Spec: appsv1.DaemonSetSpec{
					UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
						Type: appsv1.RollingUpdateDaemonSetStrategyType,
						RollingUpdate: &appsv1.RollingUpdateDaemonSet{
							MaxUnavailable: &mu,
						},
					},
				},
				Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 100},
			}, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			// 10% of 100 = 10.
			Expect(ta.resolveDaemonSetMaxUnavailable("calico-node")).To(Equal(10))
		})
	})

	Context("stalePodIPRecoveryEnabled gate", func() {
		const (
			typhaSelector      = "k8s-app=calico-typha"
			calicoNodeSelector = "k8s-app=calico-node"
		)

		BeforeEach(func() {
			// The autoscaler may degrade if there aren't enough linux nodes to satisfy
			// the expected typha scale. We don't care about scaling behavior here, so
			// allow any SetDegraded call.
			statusManager.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe()
		})

		// stale-node has InternalIP 10.0.0.2; pods are placed on it with podIP 10.0.0.1
		// to make them stale.
		ensureStaleNode := func() {
			if _, err := c.CoreV1().Nodes().Get(ctx, "stale-node", metav1.GetOptions{}); err == nil {
				return
			}
			node := CreateNode(c, "stale-node", map[string]string{"kubernetes.io/os": "linux"}, nil)
			node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.2"}}
			_, err := c.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		createStalePod := func(name, k8sApp string) {
			ensureStaleNode()
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: name, Namespace: "calico-system",
					Labels: map[string]string{"k8s-app": k8sApp},
				},
				Spec:   corev1.PodSpec{NodeName: "stale-node"},
				Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}}},
			}
			pod, err := c.CoreV1().Pods("calico-system").Create(ctx, pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			pod.Status.PodIPs = []corev1.PodIP{{IP: "10.0.0.1"}}
			_, err = c.CoreV1().Pods("calico-system").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		listPods := func(selector string) []corev1.Pod {
			pods, err := c.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{LabelSelector: selector})
			Expect(err).NotTo(HaveOccurred())
			return pods.Items
		}

		It("nil getter (default) is treated as enabled", func() {
			ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerOptionPeriod(10*time.Millisecond))
			ta.start(ctx)

			createStalePod("typha-abc", "calico-typha")
			Eventually(func() int { return len(listPods(typhaSelector)) }, 5*time.Second).Should(Equal(0))
		})

		It("getter returning true allows deletions to proceed", func() {
			ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager,
				typhaAutoscalerOptionPeriod(10*time.Millisecond),
				typhaAutoscalerOptionStalePodIPRecoveryEnabled(func() bool { return true }),
			)
			ta.start(ctx)

			createStalePod("typha-abc", "calico-typha")
			Eventually(func() int { return len(listPods(typhaSelector)) }, 5*time.Second).Should(Equal(0))
		})

		It("getter returning false suppresses all deletions", func() {
			ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager,
				typhaAutoscalerOptionPeriod(10*time.Millisecond),
				typhaAutoscalerOptionStalePodIPRecoveryEnabled(func() bool { return false }),
			)
			ta.start(ctx)

			createStalePod("typha-abc", "calico-typha")
			createStalePod("calico-node-abc", "calico-node")

			// Wait long enough for several ticks; nothing should be deleted.
			Consistently(func() int {
				return len(listPods(typhaSelector)) + len(listPods(calicoNodeSelector))
			}, 200*time.Millisecond, 20*time.Millisecond).Should(Equal(2))
		})
	})
})

func verifyTyphaReplicas(c kubernetes.Interface, expectedReplicas int) {
	EventuallyWithOffset(1, func() int32 {
		typha, err := c.AppsV1().Deployments("calico-system").Get(context.Background(), "calico-typha", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		// Just return an invalid number that will never match an expected replica count.
		if typha.Spec.Replicas == nil {
			return -1
		}
		return *typha.Spec.Replicas
	}, 5*time.Second).Should(BeEquivalentTo(expectedReplicas))
}
