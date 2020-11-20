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
	"github.com/onsi/gomega/gstruct"
	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/apimachinery/pkg/api/resource"
)

var _ = Describe("Typha rendering tests", func() {
	var installation *operator.InstallationSpec
	var registry string
	var typhaNodeTLS *render.TyphaNodeTLS
	k8sServiceEp := render.K8sServiceEndpoint{}
	BeforeEach(func() {
		registry = "test.registry.com/org"
		// Initialize a default installation to use. Each test can override this to its
		// desired configuration.
		installation = &operator.InstallationSpec{
			KubernetesProvider: operator.ProviderNone,
			//Variant ProductVariant `json:"variant,omitempty"`
			Registry: registry,
			CNI: &operator.CNISpec{
				Type: operator.PluginCalico,
			},
		}
		typhaNodeTLS = &render.TyphaNodeTLS{
			CAConfigMap: &v1.ConfigMap{},
			TyphaSecret: &v1.Secret{},
			NodeSecret:  &v1.Secret{},
		}
	})

	It("should render all resources for a default configuration", func() {
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
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		component := render.Typha(k8sServiceEp, installation, typhaNodeTLS, nil, false)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		dResource := GetResource(resources, "calico-typha", "calico-system", "", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())
		d := dResource.(*apps.Deployment)
		tc := d.Spec.Template.Spec.Containers[0]
		Expect(tc.Name).To(Equal("calico-typha"))
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(tc.Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(tc.Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
	})

	It("should include updates needed for migration of core components from kube-system namespace", func() {
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
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		component := render.Typha(k8sServiceEp, installation, typhaNodeTLS, nil, true)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

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
	It("should set TIGERA_*_SECURITY_GROUP variables when AmazonCloudIntegration is defined", func() {
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
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		aci := &operator.AmazonCloudIntegration{
			Spec: operator.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
				PodSecurityGroupID:   "sg-podsgid",
			},
		}
		component := render.Typha(k8sServiceEp, installation, typhaNodeTLS, aci, true)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		deploymentResource := GetResource(resources, "calico-typha", "calico-system", "", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())
		d := deploymentResource.(*apps.Deployment)
		tc := d.Spec.Template.Spec.Containers[0]
		Expect(tc.Name).To(Equal("calico-typha"))

		// Assert on expected env vars.
		expectedEnvVars := []v1.EnvVar{
			{Name: "TIGERA_DEFAULT_SECURITY_GROUPS", Value: "sg-nodeid,sg-masterid"},
			{Name: "TIGERA_POD_SECURITY_GROUP", Value: "sg-podsgid"},
		}
		for _, v := range expectedEnvVars {
			Expect(tc.Env).To(ContainElement(v))
		}
	})

	It("should render resourcerequirements", func() {
		rr := &v1.ResourceRequirements{
			Requests: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("250m"),
				v1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("500m"),
				v1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		installation.ComponentResources = []operator.ComponentResource{
			{
				ComponentName:        operator.ComponentNameTypha,
				ResourceRequirements: rr,
			},
		}

		component := render.Typha(k8sServiceEp, installation, typhaNodeTLS, nil, false)
		resources, _ := component.Objects()

		depResource := GetResource(resources, "calico-typha", "calico-system", "", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*apps.Deployment)

		passed := false
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == "calico-typha" {
				Expect(container.Resources).To(Equal(*rr))
				passed = true
			}
		}
		Expect(passed).To(Equal(true))
	})
})
