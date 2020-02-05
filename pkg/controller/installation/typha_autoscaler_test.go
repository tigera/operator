// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/test"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Test typha autoscaler ", func() {
	var c client.Client
	ctx := context.Background()

	calicoSystemNs := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-system",
		},
	}
	BeforeEach(func() {
		c = fake.NewFakeClientWithScheme(scheme.Scheme)
		err := c.Create(ctx, calicoSystemNs)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should get the correct number of nodes", func() {
		n1 := createNode(c, "node1")
		_ = createNode(c, "node2")

		ta := newTyphaAutoscaler(c)
		n, err := ta.getNumberOfNodes()
		Expect(err).To(BeNil())
		Expect(n).To(Equal(2))

		n1.Spec.Unschedulable = true
		err = c.Update(ctx, n1)
		Expect(err).To(BeNil())

		n, err = ta.getNumberOfNodes()
		Expect(err).To(BeNil())
		Expect(n).To(Equal(1))
	})

	It("should scale the Typha up and down in response to the number of schedulable nodes", func() {
		typhaMeta := metav1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "calico-system",
		}
		// Create a typha deployment
		typha := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: typhaMeta,
		}
		err := c.Create(ctx, typha)
		Expect(err).To(BeNil())

		// Create a few nodes
		_ = createNode(c, "node1")
		_ = createNode(c, "node2")

		// Create the autoscaler and run it
		ta := newTyphaAutoscaler(c, typhaAutoscalerPeriod(10*time.Millisecond))
		ta.run()

		verifyTyphaReplicas(c, 2)

		n3 := createNode(c, "node3")
		verifyTyphaReplicas(c, 3)

		// Verify that making a node unschedulable updates replicas.
		n3.Spec.Unschedulable = true
		err = c.Update(context.Background(), n3)
		Expect(err).To(BeNil())
		verifyTyphaReplicas(c, 2)
	})
})

func createNode(c client.Client, name string) *corev1.Node {
	node := &corev1.Node{
		TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	err := c.Create(context.Background(), node)
	Expect(err).To(BeNil())
	return node
}

func verifyTyphaReplicas(c client.Client, expectedReplicas int) {
	typha := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "calico-system",
		},
	}
	Eventually(func() int32 {
		err := test.GetResource(c, typha)
		Expect(err).To(BeNil())
		// Just return an invalid number that will never match an expected replica count.
		if typha.Spec.Replicas == nil {
			return -1
		}
		return *typha.Spec.Replicas
	}, 1*time.Second).Should(BeEquivalentTo(expectedReplicas))
}
