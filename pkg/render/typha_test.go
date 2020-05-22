// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Typha rendering tests", func() {
	var installation *operator.Installation
	var registry string
	var provider operator.Provider
	var typhaNodeTLS *render.TyphaNodeTLS
	BeforeEach(func() {
		registry = "test.registry.com/org"
		// Initialize a default installation to use. Each test can override this to its
		// desired configuration.
		installation = &operator.Installation{
			Spec: operator.InstallationSpec{
				//Variant ProductVariant `json:"variant,omitempty"`
				Registry: registry,
			},
		}
		provider = operator.ProviderNone
		typhaNodeTLS = &render.TyphaNodeTLS{
			CAConfigMap: &v1.ConfigMap{},
			TyphaSecret: &v1.Secret{},
			NodeSecret:  &v1.Secret{},
		}
	})

	It("should render all resources for a default configuration", func() {
		component := render.Typha(installation, provider, typhaNodeTLS, nil, false)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(6))

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// Typha resources
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "Deployment"},
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1beta1", kind: "PodDisruptionBudget"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})

	It("should include updates needed for migration of core components from kube-system namespace", func() {
		component := render.Typha(installation, provider, typhaNodeTLS, nil, true)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(6))

		dResource := GetResource(resources, "calico-typha", "calico-system", "", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		d := dResource.(*apps.Deployment)
		paa := d.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution
		Expect(paa).To(ContainElement(v1.PodAffinityTerm{
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "calico-typha"},
			},
			Namespaces:  []string{"kube-system"},
			TopologyKey: "kubernetes.io/hostname",
		}))
	})
})
