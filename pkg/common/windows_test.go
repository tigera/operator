// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package common

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/apis"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("GetWindowsNodes", func() {
	var (
		c      client.Client
		ctx    context.Context
		scheme *runtime.Scheme
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		Expect(v1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()

		Expect(c.Create(ctx, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "windows1",
				Labels: map[string]string{
					"kubernetes.io/os": "windows",
					"env":              "dev",
				},
				Annotations: map[string]string{
					"projectcalico.org/test": "something",
				},
			},
		})).ToNot(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "linux1",
				Labels: map[string]string{
					"kubernetes.io/os": "linux",
				},
				Annotations: map[string]string{
					"projectcalico.org/CalicoVersion": "v3.19.1",
				},
			},
		})).ToNot(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "windows2",
				Labels: map[string]string{
					"kubernetes.io/os": "windows",
					"env":              "test",
				},
				Annotations: map[string]string{
					"projectcalico.org/CalicoVersion": "v3.19.1",
				},
			},
		})).ToNot(HaveOccurred())
	})

	It("Returns windows nodes", func() {
		nodes, err := GetWindowsNodes(ctx, c)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(len(nodes)).To(Equal(2))
		nodeNames := []string{nodes[0].Name, nodes[1].Name}
		Expect(nodeNames).Should(ContainElements("windows1", "windows2"))
	})

	It("Returns windows nodes that match a filter", func() {
		nodes, err := GetWindowsNodes(ctx, c, func(n *corev1.Node) bool {
			return n.Labels["env"] == "dev"
		})

		Expect(err).ShouldNot(HaveOccurred())
		Expect(len(nodes)).To(Equal(1))
		Expect(nodes[0].Name).Should(Equal("windows1"))

		nodes, err = GetWindowsNodes(ctx, c, func(n *corev1.Node) bool {
			return n.Labels["env"] == "no-match"
		})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(len(nodes)).To(Equal(0))

		nodes, err = GetWindowsNodes(ctx, c, func(n *corev1.Node) bool {
			return n.Annotations["projectcalico.org/CalicoVersion"] != ""
		})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(len(nodes)).To(Equal(1))
		Expect(nodes[0].Name).Should(Equal("windows2"))
	})
})
