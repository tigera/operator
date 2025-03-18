// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package whisker_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/resource"

	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Applying overrides", func() {
	It("Should apply overrides", func() {

		affinity := &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "custom-affinity-key",
									Operator: corev1.NodeSelectorOpExists,
								},
							},
						},
					},
				},
			},
		}

		whiskerResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
		}

		whiskerbackendResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("11Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("11Gi"),
			},
		}

		nodeSelector := map[string]string{
			"not-zero": "an override of a default nodeSelector key",
		}

		podLabels := map[string]string{
			"foo": "bar",
		}
		podAnnotations := map[string]string{
			"baz": "qux",
		}

		tolerations := []corev1.Toleration{
			{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			},
		}

		topologyConstraints := []corev1.TopologySpreadConstraint{
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
			},
		}

		overrides := &operatorv1.WhiskerDeployment{
			Spec: &operatorv1.WhiskerDeploymentSpec{
				Template: &operatorv1.WhiskerDeploymentPodTemplateSpec{

					Metadata: &operatorv1.Metadata{
						Labels:      podLabels,
						Annotations: podAnnotations,
					},

					Spec: &operatorv1.WhiskerDeploymentPodSpec{

						Affinity: affinity,

						Containers: []operatorv1.WhiskerDeploymentContainer{

							{
								Name:      "whisker",
								Resources: whiskerResources,
							},

							{
								Name:      "whisker-backend",
								Resources: whiskerbackendResources,
							},
						},

						NodeSelector: nodeSelector,

						TopologySpreadConstraints: topologyConstraints,

						Tolerations: tolerations,
					},
				},
			},
		}

		// Must implement a function with the following definition:
		// `func GetOverriddenWhiskerDeployment(overrides *operatorv1.WhiskerDeployment) (*appsv1.Deployment, error)`
		deployment, err := GetOverriddenWhiskerDeployment(overrides)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(deployment.Spec.Template.ObjectMeta.Labels).To(Equal(podLabels))
		Expect(deployment.Spec.Template.ObjectMeta.Annotations).To(Equal(podAnnotations))

		Expect(deployment.Spec.Template.Spec.Affinity).To(Equal(affinity))

		Expect(deployment.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologyConstraints))

		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))

		Expect(deployment.Spec.Template.Spec.Tolerations).To(Equal(tolerations))

		Expect(deployment.Spec.Template.Spec.Containers[0].Resources).To(Equal(*whiskerResources))

		Expect(deployment.Spec.Template.Spec.Containers[1].Resources).To(Equal(*whiskerbackendResources))

	})
})
