// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/status"
	. "github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
		c = kfake.NewSimpleClientset(objs...)
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

		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager)
		ta.start(ctx)

		Eventually(func() error {
			schedulableNodes, linuxNodes, err := ta.getNodeCounts()
			if err != nil {
				return err
			}
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
		Expect(err).To(BeNil())

		Eventually(func() error {
			schedulableNodes, linuxNodes, err := ta.getNodeCounts()
			if err != nil {
				return err
			}
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
		Expect(err).To(BeNil())

		// Create a few nodes
		_ = CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		_ = CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux"}, nil)

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerPeriod(10*time.Millisecond))
		ta.start(ctx)

		// For clusters smaller than 3 nodes we only expect 1 replica.
		verifyTyphaReplicas(c, 1)

		// For three and four node clusters, we expect 2.
		n3 := CreateNode(c, "node3", map[string]string{"kubernetes.io/os": "linux"}, nil)
		verifyTyphaReplicas(c, 2)
		_ = CreateNode(c, "node4", map[string]string{"kubernetes.io/os": "linux"}, nil)
		verifyTyphaReplicas(c, 2)

		// For > 4 nodes, we expect redundancy with 3 replicas.
		_ = CreateNode(c, "node5", map[string]string{"kubernetes.io/os": "linux"}, nil)
		verifyTyphaReplicas(c, 3)

		// Verify that making a node unschedulable updates replicas. Should bring us back
		// down to 4 node scale.
		n3.Spec.Unschedulable = true
		_, err = c.CoreV1().Nodes().Update(ctx, n3, metav1.UpdateOptions{})
		Expect(err).To(BeNil())
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
		Expect(err).To(BeNil())

		// Create five nodes, one of which is not yet migrated
		CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node3", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node4", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "migrated"}, nil)
		CreateNode(c, "node5", map[string]string{"kubernetes.io/os": "linux", "projectcalico.org/operator-node-migration": "pre-operator"}, nil)

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerPeriod(10*time.Millisecond))
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

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerPeriod(10*time.Millisecond))
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
		Expect(err).To(BeNil())

		statusManager.On("SetDegraded", operator.ResourceScalingError, "Failed to autoscale typha - not enough linux nodes to schedule typha pods on, require 3 and have 2", mock.Anything, mock.Anything)

		// Create a few nodes
		_ = CreateNode(c, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		_ = CreateNode(c, "node2", map[string]string{"kubernetes.io/os": "linux"}, nil)
		_ = CreateNode(c, "node3", map[string]string{"kubernetes.io/os": "windows"}, nil)
		_ = CreateNode(c, "node4", map[string]string{"kubernetes.io/os": "windows"}, nil)
		_ = CreateNode(c, "node5", map[string]string{"kubernetes.io/os": "windows"}, nil)

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, nodeIndexInformer, tlw, statusManager, typhaAutoscalerPeriod(10*time.Millisecond))
		ta.start(ctx)

		// This blocks until the first run is done.
		ta.isDegraded()

		statusManager.AssertExpectations(GinkgoT())
	})
})

func verifyTyphaReplicas(c kubernetes.Interface, expectedReplicas int) {
	EventuallyWithOffset(1, func() int32 {
		typha, err := c.AppsV1().Deployments("calico-system").Get(context.Background(), "calico-typha", metav1.GetOptions{})
		Expect(err).To(BeNil())
		// Just return an invalid number that will never match an expected replica count.
		if typha.Spec.Replicas == nil {
			return -1
		}
		return *typha.Spec.Replicas
	}, 5*time.Second).Should(BeEquivalentTo(expectedReplicas))
}
