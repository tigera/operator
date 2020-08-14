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

package utils

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

var _ = Describe("provider discovery", func() {
	BeforeEach(func() {
	})

	It("should not detect a provider if with no info", func() {
		c := fake.NewSimpleClientset()
		p, e := AutoDiscoverProvider(c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderNone))
	})

	It("should detect DockerEE if a Master Node has labels prefixed with com.docker.ucp", func() {
		c := fake.NewSimpleClientset(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "master1",
				Labels: map[string]string{
					"node-role.kubernetes.io/master":    "",
					"com.docker.ucp.orchestrator.swarm": "true",
				},
			},
		})
		p, e := AutoDiscoverProvider(c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderDockerEE))
	})

	It("should detect openshift based on API resource config.openshift.io existence", func() {
		c := fake.NewSimpleClientset()
		c.Resources = []*metav1.APIResourceList{{
			GroupVersion: "config.openshift.io/v1",
		}}
		p, e := AutoDiscoverProvider(c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderOpenShift))
	})

	It("should detect GKE based on API resource networking.gke.io existence", func() {
		c := fake.NewSimpleClientset()
		c.Resources = []*metav1.APIResourceList{{
			GroupVersion: "networking.gke.io/v1",
		}}
		p, e := AutoDiscoverProvider(c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderGKE))
	})

	It("should detect EKS based on eks-certificates-controller ConfigMap", func() {
		c := fake.NewSimpleClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "eks-certificates-controller",
				Namespace: "kube-system",
			},
		})
		p, e := AutoDiscoverProvider(c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderEKS))
	})
})
