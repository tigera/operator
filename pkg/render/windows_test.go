// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/apis"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Windows-upgrade rendering tests", func() {
	var installation *operatorv1.InstallationSpec
	var cfg render.WindowsConfig

	BeforeEach(func() {
		// Initialize a default installation to use. Each test can override this to its
		// desired configuration.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderAKS,
			// Variant ProductVariant `json:"variant,omitempty"`
			CNI: &operatorv1.CNISpec{
				Type: operatorv1.PluginCalico,
			},
		}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cfg = render.WindowsConfig{
			Installation: installation,
		}
	})

	DescribeTable("should render resources only for AKS",
		func(provider operatorv1.Provider, expectedNumResources int) {
			installation.KubernetesProvider = provider

			component := render.Windows(&cfg)
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(expectedNumResources))
		},
		Entry("None", operatorv1.ProviderNone, 0),
		Entry("EKS", operatorv1.ProviderEKS, 0),
		Entry("GKE", operatorv1.ProviderGKE, 0),
		Entry("RKE2", operatorv1.ProviderRKE2, 0),
		Entry("OpenShift", operatorv1.ProviderOpenShift, 0),
		Entry("DockerEE", operatorv1.ProviderDockerEE, 0),
		Entry("AKS", operatorv1.ProviderAKS, 2),
	)

	It("should render all resources for a default configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-windows-upgrade", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-windows-upgrade", ns: "calico-system", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		component := render.Windows(&cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	Context("With calico-windows-upgrade DaemonSet overrides", func() {
		var rr1 = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}

		It("should handle calicoWindowsUpgradeDaemonSet overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			installation.CalicoWindowsUpgradeDaemonSet = &operatorv1.CalicoWindowsUpgradeDaemonSet{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.CalicoWindowsUpgradeDaemonSetSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.CalicoWindowsUpgradeDaemonSetPodSpec{
							Containers: []operatorv1.CalicoWindowsUpgradeDaemonSetContainer{
								{
									Name:      "calico-windows-upgrade",
									Resources: &rr1,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}

			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			dResource := rtest.GetResource(resources, "calico-windows-upgrade", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dResource).ToNot(BeNil())

			d := dResource.(*appsv1.DaemonSet)

			Expect(d.Labels).To(HaveLen(1))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(1))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-windows-upgrade". But the
			// daemonset object produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(1))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 1 template-level annotations
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(1))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-windows-upgrade"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
		})
	})
})
