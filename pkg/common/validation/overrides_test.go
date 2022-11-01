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

package validation

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	opv1 "github.com/tigera/operator/api/v1"
	node "github.com/tigera/operator/pkg/common/validation/calico-node"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Test overrides validation (NodeDaemonset)", func() {
	var overrides *opv1.CalicoNodeDaemonSet

	invalidRr := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			"cats": resource.MustParse("2"),
		},
	}

	BeforeEach(func() {
		overrides = &opv1.CalicoNodeDaemonSet{
			Spec: &opv1.CalicoNodeDaemonSetSpec{
				Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
					Spec: &opv1.CalicoNodeDaemonSetPodSpec{},
				},
			},
		}
	})

	It("should return an error if the metadata is invalid", func() {
		overrides.Metadata = &opv1.Metadata{
			Annotations: map[string]string{
				"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
			},
		}

		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(HavePrefix("metadata is invalid: metadata.annotations: Invalid value: \"AnnotNoUppercaseOrSpecialCharsLike=Equals\": name part must consist of alphanumeric characters"))
	})

	It("should return an error if minReadySeconds is invalid", func() {
		var invalidMinReadySeconds int32 = -1
		overrides.Spec.MinReadySeconds = &invalidMinReadySeconds
		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(Equal("spec.MinReadySeconds must be greater than or equal to 0"))
	})

	It("should return an error if pod template metadata is invalid", func() {
		overrides.Spec.Template.Metadata = &opv1.Metadata{
			Labels: map[string]string{
				"NoUppercaseOrSpecialCharsLike=Equals": "b",
			},
		}

		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Metadata is invalid: metadata.labels: Invalid value"))
	})

	It("should return an error if containers are invalid", func() {
		// Valid container name but invalid resources.
		overrides.Spec.Template.Spec.Containers = []opv1.CalicoNodeDaemonSetContainer{
			{
				Name:      "calico-node",
				Resources: &invalidRr,
			},
		}

		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Spec.Containers[\"calico-node\"] is invalid: [spec.template.spec.containers.limits[cats]: Invalid value: \"cats\""))
	})

	It("should return an error if init containers are invalid", func() {
		// Valid container name but invalid resources.
		overrides.Spec.Template.Spec.InitContainers = []opv1.CalicoNodeDaemonSetInitContainer{
			{
				Name:      "install-cni",
				Resources: &invalidRr,
			},
		}

		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Spec.InitContainers[\"install-cni\"] is invalid: [spec.template.spec.initContainers.limits[cats]: Invalid value: \"cats\""))
	})

	It("should return an error if the affinity is invalid", func() {
		overrides.Spec.Template.Spec.Affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{},
			},
		}

		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Spec.Affinity is invalid: spec.template.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms: Required value: must have at least one node selector term"))
	})

	It("should return an error if the nodeSelector is invalid", func() {
		overrides.Spec.Template.Spec.NodeSelector = map[string]string{"NoUppercaseOrSpecialCharsLike=Equals": "b"}
		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Spec.NodeSelector is invalid: spec.template.spec.nodeSelector: Invalid value: \"NoUppercaseOrSpecialCharsLike=Equals\": name part must consist of alphanumeric characters"))
	})

	It("should return an error if the tolerations are invalid", func() {
		invalidTol := corev1.Toleration{Operator: "Equal", Value: "bar", Effect: "NoSchedule"}
		overrides.Spec.Template.Spec.Tolerations = []corev1.Toleration{invalidTol}

		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Spec.Tolerations is invalid: spec.template.spec.tolerations[0].operator: Invalid value: \"Equal\": operator must be Exists when `key` is empty"))
	})
})

var _ = Describe("Test overrides validation (TyphaDeployment)", func() {
	var overrides *opv1.TyphaDeployment

	BeforeEach(func() {
		overrides = &opv1.TyphaDeployment{
			Spec: &opv1.TyphaDeploymentSpec{
				Template: &opv1.TyphaDeploymentPodTemplateSpec{
					Spec: &opv1.TyphaDeploymentPodSpec{},
				},
			},
		}
	})

	It("should accept a valid topology spread constraint", func() {
		s := metav1.LabelSelector{MatchLabels: map[string]string{"brick": "mortar"}}
		overrides.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{
			{MaxSkew: 1, TopologyKey: "realm", WhenUnsatisfiable: corev1.DoNotSchedule, LabelSelector: &s},
		}
		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).To(BeNil())
	})

	It("should return an error if there are duplicate topology spread constraints", func() {
		s := metav1.LabelSelector{MatchLabels: map[string]string{"crusty": "pizza"}}
		overrides.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{
			{MaxSkew: 1, TopologyKey: "dominion", WhenUnsatisfiable: corev1.DoNotSchedule, LabelSelector: &s},
			{MaxSkew: 1, TopologyKey: "dominion", WhenUnsatisfiable: corev1.DoNotSchedule, LabelSelector: &s},
		}
		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Spec.TopologySpreadConstraints is invalid: spec.template.spec.topologySpreadConstraints[0].{topologyKey, whenUnsatisfiable}: Duplicate value: \"{dominion, DoNotSchedule}\""))
	})

	It("should return an error if there is no topology key", func() {
		s := metav1.LabelSelector{MatchLabels: map[string]string{"tepid": "rinse"}}
		overrides.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{
			{MaxSkew: 1, WhenUnsatisfiable: corev1.DoNotSchedule, LabelSelector: &s},
		}
		err := ValidateReplicatedPodResourceOverrides(overrides, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).Should(HavePrefix("spec.Template.Spec.TopologySpreadConstraints is invalid: spec.template.spec.topologySpreadConstraints[0].topologyKey: Required value: can not be empty"))
	})
})
