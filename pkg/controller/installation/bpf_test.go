// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
)

const managedFieldsAnnotation = "operator.tigera.io/managed-fields-installation"

// trackedFields parses the consolidated managed-fields annotation on the FC.
func trackedFields(fc *v3.FelixConfiguration) map[string]string {
	raw, ok := fc.Annotations[managedFieldsAnnotation]
	if !ok {
		return nil
	}
	var fields map[string]string
	ExpectWithOffset(1, json.Unmarshal([]byte(raw), &fields)).To(Succeed())
	return fields
}

var _ = Describe("BPF functional tests", func() {
	Context("setBPFEnabledOnFelixConfiguration conflict detection", func() {
		var fc *v3.FelixConfiguration
		var enabled, notEnabled bool

		enabled = true
		notEnabled = false

		BeforeEach(func() {
			fc = &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "default",
					Annotations: map[string]string{"foo": "bar"},
				},
				Spec: v3.FelixConfigurationSpec{},
			}
		})

		It("should error when spec was modified out-of-band (tracked true, spec false)", func() {
			// Simulate: operator previously set BPFEnabled=true, user changed to false.
			fc.Annotations[managedFieldsAnnotation] = `{"BPFEnabled":"true"}`
			fc.Spec.BPFEnabled = &notEnabled
			err := setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("modified by another actor"))
		})

		It("should error when spec was modified out-of-band (tracked false, spec true)", func() {
			fc.Annotations[managedFieldsAnnotation] = `{"BPFEnabled":"false"}`
			fc.Spec.BPFEnabled = &enabled
			err := setBPFEnabledOnFelixConfiguration(fc, false)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("modified by another actor"))
		})

		It("should succeed when both are nil (fresh install)", func() {
			fc.Annotations = nil
			err := setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())
			Expect(trackedFields(fc)).To(HaveKeyWithValue("BPFEnabled", "true"))
		})

		It("should succeed when tracked matches spec", func() {
			fc.Annotations[managedFieldsAnnotation] = `{"BPFEnabled":"false"}`
			fc.Spec.BPFEnabled = &notEnabled
			err := setBPFEnabledOnFelixConfiguration(fc, false)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should update tracked value when operator changes desired value", func() {
			fc.Annotations[managedFieldsAnnotation] = `{"BPFEnabled":"false"}`
			fc.Spec.BPFEnabled = &notEnabled
			err := setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())
			Expect(trackedFields(fc)).To(HaveKeyWithValue("BPFEnabled", "true"))
		})
	})

	Context("Legacy annotation migration", func() {
		It("should migrate old per-field annotation to consolidated tracker", func() {
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
					Annotations: map[string]string{
						render.BPFOperatorAnnotation: "true",
					},
				},
				Spec: v3.FelixConfigurationSpec{
					BPFEnabled: boolPtr(true),
				},
			}

			err := setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).ShouldNot(HaveOccurred())
			// Old annotation should be removed.
			Expect(fc.Annotations).NotTo(HaveKey(render.BPFOperatorAnnotation))
			// New consolidated annotation should exist.
			Expect(trackedFields(fc)).To(HaveKeyWithValue("BPFEnabled", "true"))
		})

		It("should detect conflict after migrating legacy annotation", func() {
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
					Annotations: map[string]string{
						render.BPFOperatorAnnotation: "true",
					},
				},
				Spec: v3.FelixConfigurationSpec{
					BPFEnabled: boolPtr(false), // User changed it.
				},
			}

			err := setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("modified by another actor"))
		})
	})

	Context("Daemonset rollout completion tests", func() {
		var ds *appsv1.DaemonSet
		var bpfVolume corev1.Volume
		BeforeEach(func() {
			ds = &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: render.CalicoNodeObjectName, Image: render.CalicoNodeObjectName}},
							Volumes: []corev1.Volume{
								{Name: "other-volume", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/other/volume"}}},
							},
						},
					},
				},
			}

			bpfVolume = corev1.Volume{Name: render.BPFVolumeName}
		})

		It("should return false if volume is not found", func() {
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeFalse())
		})

		It("should return false if CurrentNumberScheduled is not matching UpdatedNumberScheduled", func() {
			ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, bpfVolume)

			ds.Status.CurrentNumberScheduled = 4
			ds.Status.UpdatedNumberScheduled = 2
			ds.Status.NumberAvailable = 4
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeFalse())
		})

		It("should return false if CurrentNumberScheduled is not matching NumberAvailable", func() {
			ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, bpfVolume)

			ds.Status.CurrentNumberScheduled = 4
			ds.Status.UpdatedNumberScheduled = 4
			ds.Status.NumberAvailable = 2
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeFalse())
		})

		It("should return true if CurrentNumberScheduled is matching NumberAvailable and CurrentNumberScheduled", func() {
			ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, bpfVolume)

			ds.Status.CurrentNumberScheduled = 4
			ds.Status.UpdatedNumberScheduled = 4
			ds.Status.NumberAvailable = 4
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeTrue())
		})
	})

	Context("BPFEnabled on daemonset variable tests", func() {
		var ds *appsv1.DaemonSet

		BeforeEach(func() {
			ds = &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: render.CalicoNodeObjectName, Image: render.CalicoNodeObjectName}},
							Volumes: []corev1.Volume{
								{Name: "other-volume", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/other/volume"}}},
							},
						},
					},
				},
			}
		})

		It("should return false if BPFEnabled ENV is nil", func() {
			result, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(BeFalse())
		})

		It("should return true if BPFEnabled ENV is set to true", func() {
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "true", ValueFrom: nil},
			}
			result, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(BeTrue())
		})

		It("should return false if BPFEnabled ENV is set to false", func() {
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "false", ValueFrom: nil},
			}
			result, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(BeFalse())
		})

		It("should return error if BPFEnabled ENV is set to an invalid string", func() {
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "invalid", ValueFrom: nil},
			}
			_, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("BPFEnabled on FelixConfiguration tests", func() {
		var fc *v3.FelixConfiguration
		var enabled, notEnabled bool

		enabled = true
		notEnabled = false

		BeforeEach(func() {
			fc = &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{},
			}
		})

		It("should return false if BPFEnabled field is nil", func() {
			result := bpfEnabledOnFelixConfig(fc)
			Expect(result).To(BeFalse())
		})

		It("should return false if BPFEnabled field is false", func() {
			fc.Spec.BPFEnabled = &notEnabled
			result := bpfEnabledOnFelixConfig(fc)
			Expect(result).To(BeFalse())
		})

		It("should return false if BPFEnabled field is true", func() {
			fc.Spec.BPFEnabled = &enabled
			result := bpfEnabledOnFelixConfig(fc)
			Expect(result).To(BeTrue())
		})
	})

	Context("setBPFEnabledOnFelixConfiguration tests", func() {
		var fc *v3.FelixConfiguration

		BeforeEach(func() {
			fc = &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{},
			}
		})

		It("should set correct annotation and spec value", func() {
			err := setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(trackedFields(fc)).To(HaveKeyWithValue("BPFEnabled", "true"))
			Expect(*fc.Spec.BPFEnabled).To(Equal(true))

			err = setBPFEnabledOnFelixConfiguration(fc, false)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(trackedFields(fc)).To(HaveKeyWithValue("BPFEnabled", "false"))
			Expect(*fc.Spec.BPFEnabled).To(Equal(false))
		})
	})
})

func boolPtr(v bool) *bool {
	return &v
}
