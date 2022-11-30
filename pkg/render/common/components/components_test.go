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

package components

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/tigera/operator/test"
)

var _ = Describe("Common components render tests", func() {
	var three int32
	var resources1 corev1.ResourceRequirements
	var resources2 corev1.ResourceRequirements
	var resources3 corev1.ResourceRequirements
	var affinity corev1.Affinity
	var nodeSelector map[string]string
	var tolerations []corev1.Toleration

	BeforeEach(func() {
		three = 3
		resources1 = corev1.ResourceRequirements{
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
		resources2 = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("2"),
				"memory": resource.MustParse("2000Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    resource.MustParse("2"),
				"memory": resource.MustParse("2000Mi"),
			},
		}
		resources3 = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
		}
		affinity = corev1.Affinity{
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
		nodeSelector = map[string]string{
			"not-zero":        "an override of a default nodeSelector key",
			"custom-selector": "value",
		}
		tolerations = []corev1.Toleration{
			{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			},
		}
	})

	DescribeTable("test ApplyDaemonSetOverrides",
		func(original func() appsv1.DaemonSet, override func() *v1.CalicoNodeDaemonSet, expectations func(set appsv1.DaemonSet)) {
			orig := original()
			template := override()
			ApplyDaemonSetOverrides(&orig, template)
			expectations(orig)
		},
		Entry("empty",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultedDaemonSet()))
			}),
		Entry("empty labels and annotations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: nil,
					},
				}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultedDaemonSet()))
			}),
		Entry("empty labels and annotations, empty spec",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: map[string]string{},
					},
					Spec: &v1.CalicoNodeDaemonSetSpec{},
				}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultedDaemonSet()))
			}),
		Entry("labels and annotations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{"test-label": "label1"},
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels: map[string]string{"test-label": "label1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels and annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						// "not-zero" label and annotation keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				// Only the labels and annotations that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						// "not-zero" label keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				// Only the labels that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						// "not-zero" annotation keys exist in the defaulted calico node.
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				// Only the annotations that don't clobber existing keys are added.
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("minReadySeconds",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						MinReadySeconds: &three,
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.MinReadySeconds = three
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template labels and annotations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels:      map[string]string{"test-pod-label": "label1"},
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template labels only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{"test-pod-label": "label1"},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template annotations only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod labels and annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod labels that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("init containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								InitContainers: []v1.CalicoNodeDaemonSetInitContainer{
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
									// Invalid init container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero2",
										Resources: &resources2,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				expected.Spec.Template.Spec.InitContainers[0].Resources = resources1
				expected.Spec.Template.Spec.InitContainers[1].Resources = resources2
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty init containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								InitContainers: []v1.CalicoNodeDaemonSetInitContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),
		Entry("containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Containers: []v1.CalicoNodeDaemonSetContainer{
									// Invalid container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				expected.Spec.Template.Spec.Containers[0].Resources = resources1
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Containers: []v1.CalicoNodeDaemonSetContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty tolerations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Tolerations: []corev1.Toleration{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Spec.Tolerations = []corev1.Toleration{}
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty nodeSelector",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								NodeSelector: map[string]string{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result).To(Equal(expected))
			}),

		Entry("affinity, nodeSelector, and tolerations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Affinity:     &affinity,
								NodeSelector: nodeSelector,
								Tolerations:  tolerations,
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Spec.Affinity = &affinity
				// only keys that don't already exist in the nodeSelector are added
				for k, v := range nodeSelector {
					if _, ok := expected.Spec.Template.Spec.NodeSelector[k]; !ok {
						expected.Spec.Template.Spec.NodeSelector[k] = v
					}
				}
				expected.Spec.Template.Spec.Tolerations = tolerations
				Expect(result.Spec.Template.Spec.Affinity).To(Equal(expected.Spec.Template.Spec.Affinity))
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),
	)

	DescribeTable("test ApplyDeploymentOverrides",
		func(original func() appsv1.Deployment, override func() *v1.TyphaDeployment, expectations func(set appsv1.Deployment)) {
			orig := original()
			template := override()
			ApplyDeploymentOverrides(&orig, template)
			expectations(orig)
		},
		Entry("empty",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{}
			},
			func(result appsv1.Deployment) {
				Expect(result).To(Equal(defaultedDeployment()))
			}),
		Entry("empty labels and annotations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: nil,
					},
				}
			},
			func(result appsv1.Deployment) {
				Expect(result).To(Equal(defaultedDeployment()))
			}),
		Entry("empty labels and annotations, empty spec",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: map[string]string{},
					},
					Spec: &v1.TyphaDeploymentSpec{},
				}
			},
			func(result appsv1.Deployment) {
				Expect(result).To(Equal(defaultedDeployment()))
			}),
		Entry("labels and annotations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{"test-label": "label1"},
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels: map[string]string{"test-label": "label1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels and annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						// "not-zero" label and annotation keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				// Only the labels and annotations that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						// "not-zero" label keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				// Only the labels that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						// "not-zero" annotation keys exist in the defaulted calico node.
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				// Only the annotations that don't clobber existing keys are added.
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("minReadySeconds",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						MinReadySeconds: &three,
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.MinReadySeconds = three
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template labels and annotations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels:      map[string]string{"test-pod-label": "label1"},
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template labels only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{"test-pod-label": "label1"},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template annotations only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod labels and annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod labels that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("init containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								InitContainers: []v1.TyphaDeploymentInitContainer{
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
									// Invalid init container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero2",
										Resources: &resources2,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				expected.Spec.Template.Spec.InitContainers[0].Resources = resources1
				expected.Spec.Template.Spec.InitContainers[1].Resources = resources2
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty init containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								InitContainers: []v1.TyphaDeploymentInitContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),
		Entry("containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Containers: []v1.TyphaDeploymentContainer{
									// Invalid container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				expected.Spec.Template.Spec.Containers[0].Resources = resources1
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Containers: []v1.TyphaDeploymentContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty tolerations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Tolerations: []corev1.Toleration{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Spec.Tolerations = []corev1.Toleration{}
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty nodeSelector",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								NodeSelector: map[string]string{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result).To(Equal(expected))
			}),

		Entry("affinity, nodeSelector, and tolerations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Affinity:     &affinity,
								NodeSelector: nodeSelector,
								Tolerations:  tolerations,
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Spec.Affinity = &affinity
				// only keys that don't already exist in the nodeSelector are added
				for k, v := range nodeSelector {
					if _, ok := expected.Spec.Template.Spec.NodeSelector[k]; !ok {
						expected.Spec.Template.Spec.NodeSelector[k] = v
					}
				}
				expected.Spec.Template.Spec.Tolerations = tolerations
				Expect(result.Spec.Template.Spec.Affinity).To(Equal(expected.Spec.Template.Spec.Affinity))
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),

		Entry("terminationGracePeriod",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								TerminationGracePeriodSeconds: ptr.Int64ToPtr(3),
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				Expect(*result.Spec.Template.Spec.TerminationGracePeriodSeconds).To(Equal(int64(3)))
			}),

		Entry("strategy",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Strategy: &v1.TyphaDeploymentStrategy{
							RollingUpdate: &appsv1.RollingUpdateDeployment{
								MaxUnavailable: ptr.IntOrStrPtr("0"),
								MaxSurge:       ptr.IntOrStrPtr("100%"),
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				Expect(result.Spec.Strategy).To(Equal(appsv1.DeploymentStrategy{
					Type: appsv1.RollingUpdateDeploymentStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDeployment{
						MaxUnavailable: ptr.IntOrStrPtr("0"),
						MaxSurge:       ptr.IntOrStrPtr("100%"),
					},
				}))
			}),
	)
})

func addContainer(cs []corev1.Container) []corev1.Container {
	// Add another container and rename them to "not-zero1" and "not-zero2".
	containers := make([]corev1.Container, 0, 2)
	var newContainer corev1.Container
	cs[0].DeepCopyInto(&newContainer)
	cs[0].Name = "not-zero1"
	cs[0].Image = "not-zero1"
	newContainer.Name = "not-zero2"
	newContainer.Image = "not-zero2"

	containers = append(containers, cs[0])
	containers = append(containers, newContainer)
	return containers

}

// defaultedDaemonSet returns a DaemonSet with its fields populated.
func defaultedDaemonSet() appsv1.DaemonSet {
	var ds appsv1.DaemonSet
	defaulter := test.NewNonZeroStructDefaulter()
	Expect(defaulter.SetDefault(&ds)).ToNot(HaveOccurred())

	ds.Spec.Template.Spec.Containers = addContainer(ds.Spec.Template.Spec.Containers)
	ds.Spec.Template.Spec.InitContainers = addContainer(ds.Spec.Template.Spec.InitContainers)
	return ds
}

// defaultedDeployment returns a Deployment with its fields populated.
func defaultedDeployment() appsv1.Deployment {
	var ds appsv1.Deployment
	defaulter := test.NewNonZeroStructDefaulter()
	Expect(defaulter.SetDefault(&ds)).ToNot(HaveOccurred())

	ds.Spec.Template.Spec.Containers = addContainer(ds.Spec.Template.Spec.Containers)
	ds.Spec.Template.Spec.InitContainers = addContainer(ds.Spec.Template.Spec.InitContainers)
	return ds
}
