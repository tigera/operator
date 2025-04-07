// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
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

package {{ .Name }}_test

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
	    {{- if affinityOverrideEnabled }}
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
		{{- end }}
        {{- if resourcesOverrideEnabled }}
		{{- range $index, $name := .ContainerNames }}
            {{ asVarName $name }}Resources := &corev1.ResourceRequirements{
                Limits: corev1.ResourceList{
                    "storage": resource.MustParse("1{{ $index }}Gi"),
                },
                Requests: corev1.ResourceList{
                    "storage": resource.MustParse("1{{ $index }}Gi"),
                },
            }
        {{- end }}
        {{- end }}
        {{- if nodeSelectorOverrideEnabled }}
		nodeSelector := map[string]string{
			"some-selector": "an override of a default nodeSelector key",
		}
		{{- end }}
		{{- if podMetaDataOverrideEnabled }}
		podLabels := map[string]string{
			"extra-label": "extra",
		}
		podAnnotations := map[string]string{
			"extra-annotation": "extra",
		}
		{{- end }}
        {{- if tolerationsOverrideEnabled }}
		tolerations := []corev1.Toleration{
			{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			},
		}
		{{- end }}
        {{- if topologySpreadConstraintsOverrideEnabled }}
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
        {{ end }}
        {{- if priorityClassOverrideEnabled }}
        priorityClassName := "priority-class"
        {{- end }}

		overrides := &operatorv1.{{ .StructPrefix }}Deployment{
			Spec: &operatorv1.{{ .StructPrefix }}DeploymentSpec{
				Template: &operatorv1.{{ .StructPrefix }}DeploymentPodTemplateSpec{
				    {{- if podMetaDataOverrideEnabled }}
					Metadata: &operatorv1.Metadata{
						Labels:      podLabels,
						Annotations: podAnnotations,
					},
					{{- end }}
					Spec: &operatorv1.{{ .StructPrefix }}DeploymentPodSpec{
					    {{- if affinityOverrideEnabled }}
						Affinity: affinity,
						{{- end }}
						{{- if resourcesOverrideEnabled }}
						Containers: []operatorv1.{{ .StructPrefix }}DeploymentContainer{
						{{- range .ContainerNames }}
							{
								Name:      "{{ . }}",
								Resources: {{ asVarName . }}Resources,
							},
                        {{- end }}
						},
						{{- end }}
						{{- if nodeSelectorOverrideEnabled }}
						NodeSelector:              nodeSelector,
						{{- end }}
						{{- if topologySpreadConstraintsOverrideEnabled }}
						TopologySpreadConstraints: topologyConstraints,
						{{- end }}
						{{- if tolerationsOverrideEnabled }}
						Tolerations:               tolerations,
						{{- end }}
						{{- if priorityClassOverrideEnabled }}
                        PriorityClassName:         priorityClassName,
                        {{- end }}
					},
				},
			},
		}

		deployment, err := GetOverridden{{ .StructPrefix }}Deployment(overrides)
		Expect(err).ShouldNot(HaveOccurred())

        {{- if podMetaDataOverrideEnabled }}
		Expect(deployment.Spec.Template.ObjectMeta.Labels).To(Equal(podLabels))
		Expect(deployment.Spec.Template.ObjectMeta.Annotations).To(Equal(podAnnotations))
		{{- end }}
		{{- if affinityOverrideEnabled }}
		Expect(deployment.Spec.Template.Spec.Affinity).To(Equal(affinity))
		{{- end }}
		{{- if topologySpreadConstraintsOverrideEnabled }}
		Expect(deployment.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologyConstraints))
		{{- end }}
		{{- if nodeSelectorOverrideEnabled }}
		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
		{{- end }}
		{{- if tolerationsOverrideEnabled }}
		Expect(deployment.Spec.Template.Spec.Tolerations).To(Equal(tolerations))
		{{- end }}
		{{- if priorityClassOverrideEnabled }}
		Expect(deployment.Spec.Template.Spec.PriorityClassName).To(Equal(priorityClassName))
		{{- end }}
        {{- if resourcesOverrideEnabled }}
		{{- range $index, $name := .ContainerNames }}
		Expect(deployment.Spec.Template.Spec.Containers[{{$index}}].Resources).To(Equal(*{{ asVarName $name }}Resources))
        {{- end }}
        {{- end }}
	})
})
