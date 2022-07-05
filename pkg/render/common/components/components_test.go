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
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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
			result := ApplyDaemonSetOverrides(&orig, template)
			expectations(*result)
		},
		Entry("nil",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return nil
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultCalicoNode()))
			}),
		Entry("empty",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultCalicoNode()))
			}),
		Entry("empty labels and annotations",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: nil,
					},
				}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultCalicoNode()))
			}),
		Entry("empty labels and annotations, empty spec",
			defaultCalicoNode,
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
				Expect(result).To(Equal(defaultCalicoNode()))
			}),
		Entry("provided labels and annotations",
			defaultCalicoNode,
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
				expected := defaultCalicoNode()
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("provided labels and annotations that are already defined",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						// "default-label" and "default-annot" exist in the default calico node.
						Labels: map[string]string{
							"test-label":    "label1",
							"default-label": "new-label",
						},
						Annotations: map[string]string{
							"default-annot": "new-annot",
							"test-annot":    "annot1",
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultCalicoNode()
				// Only the labels and annotations that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("provided minReadySeconds",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						MinReadySeconds: &three,
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultCalicoNode()
				expected.Spec.MinReadySeconds = three
				Expect(result).To(Equal(expected))
			}),
		Entry("provided pod template labels and annots",
			defaultCalicoNode,
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
				expected := defaultCalicoNode()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("provided pod labels and annotations that are already defined",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label":    "label1",
									"default-pod-label": "wont-work",
								},
								Annotations: map[string]string{
									"default-pod-annot": "wont-work",
									"test-pod-annot":    "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultCalicoNode()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("provided init container resources",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								InitContainers: []v1.CalicoNodeInitContainer{
									{
										Name:      "hostpath-init",
										Resources: &resources1,
									},
									// Invalid init container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "install-cni",
										Resources: &resources2,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultCalicoNode()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				if expected.Spec.Template.Spec.InitContainers[0].Name == "install-cni" {
					expected.Spec.Template.Spec.InitContainers[0].Resources = resources2
					expected.Spec.Template.Spec.InitContainers[1].Resources = resources1
				} else {
					expected.Spec.Template.Spec.InitContainers[0].Resources = resources1
					expected.Spec.Template.Spec.InitContainers[1].Resources = resources2
				}

				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),
		Entry("provided container resources",
			defaultCalicoNode,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Containers: []v1.CalicoNodeContainer{
									// Invalid container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "calico-node",
										Resources: &resources1,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultCalicoNode()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(1))
				expected.Spec.Template.Spec.Containers[0].Resources = resources1
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),
		Entry("provided affinity, nodeSelector, and tolerations",
			defaultCalicoNode,
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
				expected := defaultCalicoNode()
				expected.Spec.Template.Spec.Affinity = &affinity
				expected.Spec.Template.Spec.NodeSelector = nodeSelector
				expected.Spec.Template.Spec.Tolerations = tolerations
				Expect(result.Spec.Template.Spec.Affinity).To(Equal(expected.Spec.Template.Spec.Affinity))
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),
	)
})

// defaultCalicoNode returns a DaemonSet that is similar to what the operator
// creates for calico-node.
func defaultCalicoNode() appsv1.DaemonSet {
	var terminationGracePeriod int64 = 5
	fileOrCreate := corev1.HostPathFileOrCreate
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	two := intstr.FromInt(2)

	installCniInit := corev1.Container{
		Name:    "install-cni",
		Image:   "docker.io/calico/cni:master",
		Command: []string{"/opt/cni/bin/install"},
		Env: []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		},
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(true),
		},
	}
	rootUID := int64(0)
	hostPathInit := corev1.Container{
		Name:  "hostpath-init",
		Image: "docker.io/calico/node:master",
		Env: []corev1.EnvVar{
			{Name: "NODE_USER_ID", Value: "999"},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				MountPath: "/var/run",
				Name:      "var-run",
				ReadOnly:  false,
			},
			{
				MountPath: "/var/lib",
				Name:      "var-lib",
				ReadOnly:  false,
			},
			{
				MountPath: "/var/log",
				Name:      "var-log",
				ReadOnly:  false,
			},
		},
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: &rootUID,
		},
		Command: []string{"sh", "-c", "calico-node -hostpath-init"},
	}

	calicoNode := corev1.Container{
		Name:  "calico-node",
		Image: "docker.io/calico/node:master",
		Resources: corev1.ResourceRequirements{
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
		},
		SecurityContext: &corev1.SecurityContext{Privileged: ptr.BoolToPtr(true)},
		Env: []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
		},
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run/nodeagent", Name: "policysync"},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Host: "localhost",
					Path: "/liveness",
					Port: intstr.FromInt(9099),
				},
			},
			TimeoutSeconds: 10,
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}}},
			// Set the TimeoutSeconds greater than the default of 1 to allow additional time on loaded nodes.
			// This timeout should be less than the PeriodSeconds.
			TimeoutSeconds: 5,
			PeriodSeconds:  10,
		},
		Lifecycle: &corev1.Lifecycle{
			PreStop: &corev1.Handler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-shutdown"}}},
		},
	}

	return appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: "calico-system",
			Labels: map[string]string{
				"default-label": "label1",
			},
			Annotations: map[string]string{
				"default-annot": "annot1",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"default-pod-label": "label2",
					},
					Annotations: map[string]string{
						"default-pod-annot": "annotation2",
					},
				},
				Spec: corev1.PodSpec{
					Tolerations: rmeta.TolerateAll,
					Affinity: &corev1.Affinity{
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
					},
					NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: "pullSecret1",
						},
					},
					ServiceAccountName:            "calico-node",
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                []corev1.Container{installCniInit, hostPathInit},
					Containers:                    []corev1.Container{calicoNode},
					Volumes: []corev1.Volume{
						{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
						{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
						{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
						{Name: "var-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}}},
						{Name: "var-lib", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib"}}},
						{Name: "var-log", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
					},
				},
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &two,
				},
			},
		},
	}
}
