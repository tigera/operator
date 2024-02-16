// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
	"strconv"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"

	"github.com/tigera/operator/pkg/render"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/apps"
)

var _ = Describe("BPF functional tests", func() {

	Context("Annotations validation tests", func() {
		var fc *crdv1.FelixConfiguration
		var textTrue, textFalse string
		var enabled, notEnabled bool

		textTrue = strconv.FormatBool(true)
		textFalse = strconv.FormatBool(false)

		enabled = true
		notEnabled = false

		BeforeEach(func() {
			fc = &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{},
			}
		})

		It("should return error if the value is not a boolean", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = "NotBoolean"
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is nil and the spec field is not", func() {
			fc.Spec.BPFEnabled = &enabled
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is not nil and the spec field is", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textFalse
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is true and the spec field is false", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textTrue
			fc.Spec.BPFEnabled = &notEnabled
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is false and the spec field is true", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textFalse
			fc.Spec.BPFEnabled = &enabled
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return valid if both annotation and the spec field are nil", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = "NotBoolean"
			err := bpfValidateAnnotations(fc)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return valid if the annotation is false and the spec field is false", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textFalse
			fc.Spec.BPFEnabled = &notEnabled
			err := bpfValidateAnnotations(fc)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return valid if the annotation is true and the spec field is true", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textTrue
			fc.Spec.BPFEnabled = &enabled
			err := bpfValidateAnnotations(fc)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("Daemonset rollout completion tests", func() {
		var ds *appsv1.DaemonSet
		var bpfVolume corev1.Volume
		BeforeEach(func() {
			ds = &apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: labels},
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
})
