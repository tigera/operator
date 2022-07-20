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

package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("core labels and annotations handlers", func() {
	var (
		comps = emptyComponents()
		i     = &operatorv1.Installation{}
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &operatorv1.Installation{}
	})

	Context("annotations", func() {
		Context("calico-node", func() {
			It("should not error for no annotations", func() {
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil annotations", func() {
				comps.node.Annotations = nil
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add annotations to the installation", func() {
				comps.node.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove annotations added by kubernetes", func() {
				comps.node.Annotations = map[string]string{
					"deprecated.daemonset.template.generation": "42",
					"foo":                        "bar",
					"kubectl.kubernetes.io/test": "something",
				}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same annotation is in the resource and the installation", func() {
				comps.node.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Metadata.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the annotation key exists in the resource and the installation but values differ", func() {
				comps.node.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
			It("should error if the annotation exists in the installation but not the resource", func() {
				comps.node.Annotations = map[string]string{}
				ensureEmptyCalicoNodeDaemonSetMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-node pod template spec", func() {
			It("should not error for no annotations", func() {
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil annotations", func() {
				comps.node.Spec.Template.Annotations = nil
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add annotations to the installation", func() {
				comps.node.Spec.Template.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove annotations added by kubernetes", func() {
				comps.node.Spec.Template.Annotations = map[string]string{
					"deprecated.daemonset.template.generation": "42",
					"foo":                        "bar",
					"kubectl.kubernetes.io/test": "something",
				}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same annotation is in the resource and the installation", func() {
				comps.node.Spec.Template.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the annotation key exists in the resource and the installation but values differ", func() {
				comps.node.Spec.Template.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
			It("should error if the annotation exists in the installation but not the resource", func() {
				comps.node.Spec.Template.Annotations = map[string]string{}
				ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-kube-controllers", func() {
			It("should not error for no annotations", func() {
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil annotations", func() {
				comps.kubeControllers.Annotations = nil
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add annotations to the installation", func() {
				comps.kubeControllers.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove annotations added by kubernetes", func() {
				comps.kubeControllers.Annotations = map[string]string{
					"kubectl.kubernetes.io/whatever": "whatever",
					"foo":                            "bar",
					"kubectl.kubernetes.io/test":     "something",
				}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same annotation is in the resource and the installation", func() {
				comps.kubeControllers.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Metadata.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the annotation key exists in the resource and the installation but values differ", func() {
				comps.kubeControllers.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
			It("should error if the annotation exists in the installation but not the resource", func() {
				comps.kubeControllers.Annotations = map[string]string{}
				ensureEmptyCalicoKubeControllersDeploymentMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-kube-controllers pod template spec", func() {
			It("should not error for no annotations", func() {
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil annotations", func() {
				comps.kubeControllers.Spec.Template.Annotations = nil
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add annotations to the installation", func() {
				comps.kubeControllers.Spec.Template.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove annotations added by kubernetes", func() {
				comps.kubeControllers.Spec.Template.Annotations = map[string]string{
					"deprecated.daemonset.template.generation": "42",
					"foo":                        "bar",
					"kubectl.kubernetes.io/test": "something",
				}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same annotation is in the resource and the installation", func() {
				comps.kubeControllers.Spec.Template.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the annotation key exists in the resource and the installation but values differ", func() {
				comps.kubeControllers.Spec.Template.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
			It("should error if the annotation exists in the installation but not the resource", func() {
				comps.kubeControllers.Spec.Template.Annotations = map[string]string{}
				ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-typha", func() {
			It("should not error for no annotations", func() {
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil annotations", func() {
				comps.typha.Annotations = nil
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add annotations to the installation", func() {
				comps.typha.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove annotations added by kubernetes", func() {
				comps.typha.Annotations = map[string]string{
					"kubectl.kubernetes.io/whatever": "whatever",
					"foo":                            "bar",
					"kubectl.kubernetes.io/test":     "something",
				}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same annotation is in the resource and the installation", func() {
				comps.typha.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentMetadata(i)
				i.Spec.TyphaDeployment.Metadata.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the annotation key exists in the resource and the installation but values differ", func() {
				comps.typha.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentMetadata(i)
				i.Spec.TyphaDeployment.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
			It("should error if the annotation exists in the installation but not the resource", func() {
				comps.typha.Annotations = map[string]string{}
				ensureEmptyTyphaDeploymentMetadata(i)
				i.Spec.TyphaDeployment.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-typha pod template spec", func() {
			It("should not error for no annotations", func() {
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil annotations", func() {
				comps.typha.Spec.Template.Annotations = nil
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add annotations to the installation", func() {
				comps.typha.Spec.Template.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove annotations added by kubernetes", func() {
				comps.typha.Spec.Template.Annotations = map[string]string{
					"kubectl.kubernetes.io/test2": "something2",
					"foo":                         "bar",
					"kubectl.kubernetes.io/test":  "something",
				}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same annotation is in the resource and the installation", func() {
				comps.typha.Spec.Template.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentPodTemplateMetadata(i)
				i.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations = map[string]string{"foo": "bar"}
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the annotation key exists in the resource and the installation but values differ", func() {
				comps.typha.Spec.Template.Annotations = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentPodTemplateMetadata(i)
				i.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
			It("should error if the annotation exists in the installation but not the resource", func() {
				comps.typha.Spec.Template.Annotations = map[string]string{}
				ensureEmptyTyphaDeploymentPodTemplateMetadata(i)
				i.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations = map[string]string{"foo": "baz"}
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
		})
	})

	Context("labels", func() {
		Context("calico-node", func() {
			It("should not error for no labels", func() {
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil labels", func() {
				comps.node.Labels = nil
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add labels to the installation", func() {
				comps.node.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Labels).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove standard labels the operator expects", func() {
				comps.node.Labels = map[string]string{
					"k8s-app": "calico-node",
					"foo":     "bar",
				}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Labels).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same label is in the resource and the installation", func() {
				comps.node.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Metadata.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Labels).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the label key exists in the resource and the installation but values differ", func() {
				comps.node.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
			It("should error if the label exists in the installation but not the resource", func() {
				comps.node.Labels = map[string]string{}
				ensureEmptyCalicoNodeDaemonSetMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-node pod template spec", func() {
			It("should not error for no labels", func() {
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil labels", func() {
				comps.node.Spec.Template.Labels = nil
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add labels to the installation", func() {
				comps.node.Spec.Template.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove labels added by kubernetes", func() {
				comps.node.Spec.Template.Labels = map[string]string{
					"k8s-app": "calico-node",
					"foo":     "bar",
				}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same label is in the resource and the installation", func() {
				comps.node.Spec.Template.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the label key exists in the resource and the installation but values differ", func() {
				comps.node.Spec.Template.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
			It("should error if the label exists in the installation but not the resource", func() {
				comps.node.Spec.Template.Labels = map[string]string{}
				ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-kube-controllers", func() {
			It("should not error for no labels", func() {
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil labels", func() {
				comps.kubeControllers.Labels = nil
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add labels to the installation", func() {
				comps.kubeControllers.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove labels added by kubernetes", func() {
				comps.kubeControllers.Labels = map[string]string{
					"kubectl.kubernetes.io/whatever": "whatever",
					"foo":                            "bar",
					"kubectl.kubernetes.io/test":     "something",
				}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same label is in the resource and the installation", func() {
				comps.kubeControllers.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Metadata.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the label key exists in the resource and the installation but values differ", func() {
				comps.kubeControllers.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
			It("should error if the label exists in the installation but not the resource", func() {
				comps.kubeControllers.Labels = map[string]string{}
				ensureEmptyCalicoKubeControllersDeploymentMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-kube-controllers pod template spec", func() {
			It("should not error for no labels", func() {
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil labels", func() {
				comps.kubeControllers.Spec.Template.Labels = nil
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add labels to the installation", func() {
				comps.kubeControllers.Spec.Template.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove labels added by kubernetes", func() {
				comps.kubeControllers.Spec.Template.Labels = map[string]string{
					"deprecated.daemonset.template.generation": "42",
					"foo":                        "bar",
					"kubectl.kubernetes.io/test": "something",
				}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same label is in the resource and the installation", func() {
				comps.kubeControllers.Spec.Template.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the label key exists in the resource and the installation but values differ", func() {
				comps.kubeControllers.Spec.Template.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
			It("should error if the label exists in the installation but not the resource", func() {
				comps.kubeControllers.Spec.Template.Labels = map[string]string{}
				ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-typha", func() {
			It("should not error for no labels", func() {
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil labels", func() {
				comps.typha.Labels = nil
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add labels to the installation", func() {
				comps.typha.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove labels added by kubernetes", func() {
				comps.typha.Labels = map[string]string{
					"kubectl.kubernetes.io/whatever": "whatever",
					"foo":                            "bar",
					"kubectl.kubernetes.io/test":     "something",
				}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same label is in the resource and the installation", func() {
				comps.typha.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentMetadata(i)
				i.Spec.TyphaDeployment.Metadata.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the label key exists in the resource and the installation but values differ", func() {
				comps.typha.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentMetadata(i)
				i.Spec.TyphaDeployment.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
			It("should error if the label exists in the installation but not the resource", func() {
				comps.typha.Labels = map[string]string{}
				ensureEmptyTyphaDeploymentMetadata(i)
				i.Spec.TyphaDeployment.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
		})
		Context("calico-typha pod template spec", func() {
			It("should not error for no labels", func() {
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil labels", func() {
				comps.typha.Spec.Template.Labels = nil
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add labels to the installation", func() {
				comps.typha.Spec.Template.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove labels added by kubernetes", func() {
				comps.typha.Spec.Template.Labels = map[string]string{
					"kubectl.kubernetes.io/test2": "something2",
					"foo":                         "bar",
					"kubectl.kubernetes.io/test":  "something",
				}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same label is in the resource and the installation", func() {
				comps.typha.Spec.Template.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentPodTemplateMetadata(i)
				i.Spec.TyphaDeployment.Spec.Template.Metadata.Labels = map[string]string{"foo": "bar"}
				Expect(handleLabels(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Metadata.Labels).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the label key exists in the resource and the installation but values differ", func() {
				comps.typha.Spec.Template.Labels = map[string]string{
					"foo": "bar",
				}
				ensureEmptyTyphaDeploymentPodTemplateMetadata(i)
				i.Spec.TyphaDeployment.Spec.Template.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
			It("should error if the label exists in the installation but not the resource", func() {
				comps.typha.Spec.Template.Labels = map[string]string{}
				ensureEmptyTyphaDeploymentPodTemplateMetadata(i)
				i.Spec.TyphaDeployment.Spec.Template.Metadata.Labels = map[string]string{"foo": "baz"}
				Expect(handleLabels(&comps, i)).To(HaveOccurred())
			})
		})
	})
})
