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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/controller/migration/convert/helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	operatorv1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("core handler", func() {
	var (
		comps = emptyComponents()
		i     = &operatorv1.Installation{}
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &operatorv1.Installation{}
	})
	Context("resource migration", func() {
		It("should not migrate resource requirements if none are set", func() {
			err := handleCore(&comps, i)
			Expect(err).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(BeEmpty())
		})

		var rqs1 = v1.ResourceRequirements{
			Limits: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("500m"),
				v1.ResourceMemory: resource.MustParse("500Mi"),
			},
			Requests: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("250m"),
				v1.ResourceMemory: resource.MustParse("64Mi"),
			},
		}
		var rqs2 = v1.ResourceRequirements{
			Limits: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("120m"),
				v1.ResourceMemory: resource.MustParse("100Mi"),
			},
			Requests: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("60m"),
				v1.ResourceMemory: resource.MustParse("50Mi"),
			},
		}
		var rqs3 = v1.ResourceRequirements{
			Limits: v1.ResourceList{
				v1.ResourceStorage: resource.MustParse("10G"),
			},
			Requests: v1.ResourceList{
				v1.ResourceStorage: resource.MustParse("10G"),
			},
		}

		It("should migrate resources from calico-node if they are set", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = rqs1
			comps.node.Spec.Template.Spec.InitContainers[0].Resources = rqs2
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())

			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.CalicoNodeDaemonSetContainer{
				Name:      "calico-node",
				Resources: &rqs1,
			}))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(ConsistOf(operatorv1.CalicoNodeDaemonSetInitContainer{
				Name:      "install-cni",
				Resources: &rqs2,
			}))
		})

		It("should migrate resources from kube-controllers if they are set", func() {
			comps.kubeControllers.Spec.Template.Spec.Containers[0].Resources = rqs1
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.CalicoKubeControllersDeploymentContainer{
				Name:      "calico-kube-controllers",
				Resources: &rqs1,
			}))
		})

		It("should migrate resources from typha if they are set", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Resources = rqs1
			comps.typha.Spec.Template.Spec.InitContainers[0].Resources = rqs2
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.TyphaDeploymentContainer{
				Name:      "calico-typha",
				Resources: &rqs1,
			}))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers).To(ConsistOf(operatorv1.TyphaDeploymentInitContainer{
				Name:      "typha-certs-key-cert-provisioner",
				Resources: &rqs2,
			}))
		})

		It("should migrate resources from all 3 components", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = rqs1
			comps.node.Spec.Template.Spec.InitContainers[0].Resources = rqs2

			comps.kubeControllers.Spec.Template.Spec.Containers[0].Resources = rqs1

			comps.typha.Spec.Template.Spec.Containers[0].Resources = rqs1
			comps.typha.Spec.Template.Spec.InitContainers[0].Resources = rqs2

			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())

			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.CalicoNodeDaemonSetContainer{
				Name:      "calico-node",
				Resources: &rqs1,
			}))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(ConsistOf(operatorv1.CalicoNodeDaemonSetInitContainer{
				Name:      "install-cni",
				Resources: &rqs2,
			}))
			Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.CalicoKubeControllersDeploymentContainer{
				Name:      "calico-kube-controllers",
				Resources: &rqs1,
			}))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.TyphaDeploymentContainer{
				Name:      "calico-typha",
				Resources: &rqs1,
			}))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers).To(ConsistOf(operatorv1.TyphaDeploymentInitContainer{
				Name:      "typha-certs-key-cert-provisioner",
				Resources: &rqs2,
			}))
		})

		It("should not add a duplicate resources when already set", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = rqs1
			i.Spec.ComponentResources = append(i.Spec.ComponentResources, operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameNode,
				ResourceRequirements: &rqs1,
			})
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.CalicoNodeDaemonSetContainer{
				Name:      "calico-node",
				Resources: &rqs1,
			}))
		})

		It("should use the new CalicoNodeDaemonSet field over the deprecated ComponentResource", func() {
			// Set the new component resource override for the calico-node container.
			helpers.EnsureCalicoNodeContainersNotNil(i)
			helpers.EnsureCalicoNodeInitContainersNotNil(i)
			i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = []operatorv1.CalicoNodeDaemonSetContainer{
				{
					Name:      "calico-node",
					Resources: &rqs1,
				},
			}
			i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = []operatorv1.CalicoNodeDaemonSetInitContainer{
				{
					Name:      "install-cni",
					Resources: &rqs3,
				},
			}

			// Set the deprecated ComponentResources for calico-node.
			i.Spec.ComponentResources = append(i.Spec.ComponentResources, operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameNode,
				ResourceRequirements: &rqs2,
			})

			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.CalicoNodeDaemonSetContainer{
				Name:      "calico-node",
				Resources: &rqs1,
			}))
			Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(ConsistOf(operatorv1.CalicoNodeDaemonSetInitContainer{
				Name:      "install-cni",
				Resources: &rqs3,
			}))
		})

		It("should use the new CalicoKubeControllersDeployment field over the deprecated ComponentResource", func() {
			// Set the new component resource override.
			helpers.EnsureKubeControllersContainersNotNil(i)
			i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = []operatorv1.CalicoKubeControllersDeploymentContainer{
				{
					Name:      "calico-kube-controllers",
					Resources: &rqs1,
				},
			}

			// Set the deprecated ComponentResources for calico-node.
			i.Spec.ComponentResources = append(i.Spec.ComponentResources, operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameKubeControllers,
				ResourceRequirements: &rqs2,
			})

			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.CalicoKubeControllersDeploymentContainer{
				Name:      "calico-kube-controllers",
				Resources: &rqs1,
			}))
		})

		It("should use the new TyphaDeployment field over the deprecated ComponentResource", func() {
			// Set the new component resource override.
			helpers.EnsureTyphaContainersNotNil(i)
			helpers.EnsureTyphaInitContainersNotNil(i)
			i.Spec.TyphaDeployment.Spec.Template.Spec.Containers = []operatorv1.TyphaDeploymentContainer{
				{
					Name:      "calico-typha",
					Resources: &rqs1,
				},
			}
			i.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers = []operatorv1.TyphaDeploymentInitContainer{
				{
					Name:      "typha-certs-key-cert-provisioner",
					Resources: &rqs2,
				},
			}

			// Set the deprecated ComponentResources for calico-node.
			i.Spec.ComponentResources = append(i.Spec.ComponentResources, operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameTypha,
				ResourceRequirements: &rqs3,
			})

			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(HaveLen(0))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers).To(ConsistOf(operatorv1.TyphaDeploymentInitContainer{
				Name:      "typha-certs-key-cert-provisioner",
				Resources: &rqs2,
			}))
			Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.Containers).To(ConsistOf(operatorv1.TyphaDeploymentContainer{
				Name:      "calico-typha",
				Resources: &rqs1,
			}))
		})

		It("should return an error if the calico-node container resources do not match the deprecated ComponentResource", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = rqs1

			i.Spec.ComponentResources = append(i.Spec.ComponentResources, operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameNode,
				ResourceRequirements: &rqs2,
			})

			err := handleCore(&comps, i)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("Resources for the component container \"calico-node\" did not match between Installation and migration source."))
		})

		It("should return an error if the calico-node container resources do not match those in CalicoNodeDaemonSetContainer", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = rqs1

			helpers.EnsureCalicoNodeContainersNotNil(i)
			i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = []operatorv1.CalicoNodeDaemonSetContainer{
				{
					Name:      "calico-node",
					Resources: &rqs2,
				},
			}

			err := handleCore(&comps, i)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("Resources for the component container \"calico-node\" did not match between Installation and migration source."))
		})

		It("should return an error if the calico-kube-controllers container resources do not match the deprecated ComponentResource", func() {
			comps.kubeControllers.Spec.Template.Spec.Containers[0].Resources = rqs1

			i.Spec.ComponentResources = append(i.Spec.ComponentResources, operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameKubeControllers,
				ResourceRequirements: &rqs2,
			})

			err := handleCore(&comps, i)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("Resources for the component container \"calico-kube-controllers\" did not match between Installation and migration source."))
		})

		It("should return an error if the calico-kube-controllers container resources do not match those in CalicoKubeControllersDeploymentContainer", func() {
			comps.kubeControllers.Spec.Template.Spec.Containers[0].Resources = rqs1

			helpers.EnsureKubeControllersContainersNotNil(i)
			i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = []operatorv1.CalicoKubeControllersDeploymentContainer{
				{
					Name:      "calico-kube-controllers",
					Resources: &rqs2,
				},
			}

			err := handleCore(&comps, i)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("Resources for the component container \"calico-kube-controllers\" did not match between Installation and migration source."))
		})

		It("should return an error if the calico-typha container resources do not match the deprecated ComponentResource", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Resources = rqs1

			i.Spec.ComponentResources = append(i.Spec.ComponentResources, operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameTypha,
				ResourceRequirements: &rqs2,
			})

			err := handleCore(&comps, i)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("Resources for the component container \"calico-typha\" did not match between Installation and migration source."))
		})

		It("should return an error if the calico-typha container resources do not match those in TyphaDeploymentContainer", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Resources = rqs1

			helpers.EnsureTyphaContainersNotNil(i)
			i.Spec.TyphaDeployment.Spec.Template.Spec.Containers = []operatorv1.TyphaDeploymentContainer{
				{
					Name:      "calico-typha",
					Resources: &rqs2,
				},
			}

			err := handleCore(&comps, i)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("Resources for the component container \"calico-typha\" did not match between Installation and migration source."))
		})
	})

	Context("nodeSelector", func() {
		aff1 := &corev1.Affinity{
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

		aff2 := aff1.DeepCopy()
		aff2.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Key = "another-key"

		emptyAff := &v1.Affinity{}

		Describe("calico-node", func() {
			It("should not error for no nodeSelector", func() {
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for nil nodeSelector", func() {
				comps.node.Spec.Template.Spec.NodeSelector = nil
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add nodeSelector to the installation", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "bar"}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove linux OS nodeSelector terms", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{
					"beta.kubernetes.io/os": "linux",
					"foo":                   "bar",
					"kubernetes.io/os":      "linux",
				}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the migration nodeSelector is set", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{
					"projectcalico.org/operator-node-migration": "pre-operator",
				}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				// We don't add the migration nodeSelector to the installation.
				Expect(i.Spec.CalicoNodeDaemonSet).To(BeNil())
			})
			It("should not error if the same nodeSelector is in the resource and the installation", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{
					"foo":              "bar",
					"kubernetes.io/os": "linux",
				}
				// We remove the OS nodeSelector key/value pair so they are equal
				helpers.EnsureCalicoNodeNodeSelectorNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = map[string]string{
					"foo": "bar",
				}

				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the nodeSelector key exists in the resource and the installation but values differ", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "bar"}
				helpers.EnsureCalicoNodeNodeSelectorNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "baz"}
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should error if the nodeSelector exists in the installation but not the resource", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{}
				helpers.EnsureCalicoNodeNodeSelectorNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "baz"}
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should not error for empty affinity", func() {
				comps.node.Spec.Template.Spec.Affinity = &v1.Affinity{}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(Equal(comps.node.Spec.Template.Spec.Affinity))
			})
			It("should not error for nil affinity", func() {
				comps.node.Spec.Template.Spec.Affinity = nil
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoNodeDaemonSet).To(BeNil())
			})
			It("should not error if the same affinity is in the resource and the installation", func() {
				comps.node.Spec.Template.Spec.Affinity = aff1
				helpers.EnsureCalicoNodePodSpecNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = aff1

				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(*i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*aff1))
			})
			It("should error if the affinity exists in the resource and the installation but values differ", func() {
				comps.node.Spec.Template.Spec.Affinity = aff1
				helpers.EnsureCalicoNodePodSpecNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = aff2

				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should error if the affinity exists in the installation but not the resource", func() {
				helpers.EnsureCalicoNodePodSpecNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = aff1
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("shouldn't error for aks affinity on aks", func() {
				aff := &v1.Affinity{
					NodeAffinity: &v1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
							NodeSelectorTerms: []v1.NodeSelectorTerm{{
								MatchExpressions: []v1.NodeSelectorRequirement{{
									Key:      "type",
									Operator: v1.NodeSelectorOpNotIn,
									Values:   []string{"virtual-kubelet"},
								}},
							}},
						},
					},
				}
				comps.node.Spec.Template.Spec.Affinity = aff
				i.Spec.KubernetesProvider = operatorv1.ProviderAKS
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(*i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*aff))
			})
			It("should not error for other affinities on aks", func() {
				aff := &v1.Affinity{
					NodeAffinity: &v1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
							NodeSelectorTerms: []v1.NodeSelectorTerm{{
								MatchExpressions: []v1.NodeSelectorRequirement{{
									Key:      "type",
									Operator: v1.NodeSelectorOpExists,
								}},
							}},
						},
					},
				}
				comps.node.Spec.Template.Spec.Affinity = aff
				i.Spec.KubernetesProvider = operatorv1.ProviderAKS
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(*i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*aff))
			})
		})
		Describe("typha", func() {
			It("should not error for nil nodeSelector", func() {
				comps.typha.Spec.Template.Spec.NodeSelector = nil
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add nodeSelector to the installation", func() {
				comps.typha.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "bar"}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove linux OS nodeSelector terms", func() {
				comps.typha.Spec.Template.Spec.NodeSelector = map[string]string{
					"beta.kubernetes.io/os": "linux",
					"foo":                   "bar",
					"kubernetes.io/os":      "linux",
				}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same nodeSelector is in the resource and the installation", func() {
				comps.typha.Spec.Template.Spec.NodeSelector = map[string]string{
					"foo":              "bar",
					"kubernetes.io/os": "linux",
				}
				// We remove the OS nodeSelector key/value pair so they are equal
				helpers.EnsureTyphaNodeSelectorNotNil(i)
				i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector = map[string]string{
					"foo": "bar",
				}

				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the nodeSelector key exists in the resource and the installation but values differ", func() {
				comps.typha.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "bar"}
				helpers.EnsureTyphaNodeSelectorNotNil(i)
				i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "baz"}
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should error if the nodeSelector exists in the installation but not the resource", func() {
				comps.typha.Spec.Template.Spec.NodeSelector = map[string]string{}
				helpers.EnsureTyphaNodeSelectorNotNil(i)
				i.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "baz"}
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})

			DescribeTable("should handle affinity",
				func(compAffinity *corev1.Affinity, installNewAffinity *corev1.Affinity, installOldAffinity *corev1.Affinity, expectedAffinity *corev1.Affinity, expectedErr bool) {
					if compAffinity != nil {
						comps.typha.Spec.Template.Spec.Affinity = compAffinity
					}
					if installOldAffinity != nil {
						oldAff := &operatorv1.TyphaAffinity{
							NodeAffinity: &operatorv1.NodeAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution: installOldAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
							},
						}
						i.Spec.TyphaAffinity = oldAff
					}
					if installNewAffinity != nil {
						helpers.EnsureTyphaPodSpecNotNil(i)
						i.Spec.TyphaDeployment.Spec.Template.Spec.Affinity = installNewAffinity
					}

					err := handleNodeSelectors(&comps, i)
					if expectedErr {
						Expect(err).To(HaveOccurred())
					} else {
						Expect(err).To(BeNil())

						if compAffinity != nil {
							Expect(*i.Spec.TyphaDeployment.Spec.Template.Spec.Affinity).To(Equal(*compAffinity))
						} else {
							Expect(i.Spec.TyphaDeployment).To(BeNil())
						}
						// We always expect the old TyphaAffinity to be cleared.
						Expect(i.Spec.TyphaAffinity).To(BeNil())
					}
				},
				// empty affinity
				Entry("no affinity", nil, nil, nil, nil, false),
				Entry("empty affinity", emptyAff, emptyAff, nil, emptyAff, false),
				// affinity on typha component only
				Entry("only typha has affinity", aff1, nil, nil, aff1, false),
				// affinity on install only
				Entry("only install has affinity (new affinity field only)", nil, aff1, nil, nil, true),
				Entry("only install has affinity (old affinity field only)", nil, nil, aff1, nil, true),
				Entry("only install has affinity (both affinity fields)", nil, aff1, aff1, nil, true),
				Entry("only install has affinity (both affinity fields differ)", nil, aff1, aff2, nil, true),
				// same affinities
				Entry("typha and the installation have the same affinity (new affinity field only)", aff1, aff1, nil, aff1, false),
				Entry("typha and the installation have the same affinity (old affinity field only)", aff1, nil, aff1, aff1, false),
				Entry("typha and the installation have the same affinity (both affinity fields equal)", aff1, aff1, aff1, aff1, false),
				Entry("typha and the installation have the same affinity (both affinity fields differ)", aff1, aff1, aff2, aff1, false),
				// different affinities
				Entry("typha and the installation have different affinities (new affinity field only)", aff1, aff2, nil, nil, true),
				Entry("typha and the installation have different affinities (old affinity field only)", aff1, nil, aff2, nil, true),
				Entry("typha and the installation have different affinities (both affinity fields equal)", aff1, aff2, aff2, nil, true),
				Entry("typha and the installation have different affinities (both affinity fields differ)", aff1, aff2, aff1, nil, true),
			)

			It("shouldn't error for aks affinity on aks", func() {
				aff := &v1.Affinity{
					NodeAffinity: &v1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
							NodeSelectorTerms: []v1.NodeSelectorTerm{{
								MatchExpressions: []v1.NodeSelectorRequirement{{
									Key:      "type",
									Operator: v1.NodeSelectorOpNotIn,
									Values:   []string{"virtual-kubelet"},
								}},
							}},
						},
					},
				}
				comps.typha.Spec.Template.Spec.Affinity = aff
				i.Spec.KubernetesProvider = operatorv1.ProviderAKS
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(*i.Spec.TyphaDeployment.Spec.Template.Spec.Affinity).To(Equal(*aff))
			})
			It("should not error for other affinities on aks", func() {
				aff := &v1.Affinity{
					NodeAffinity: &v1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
							NodeSelectorTerms: []v1.NodeSelectorTerm{{
								MatchExpressions: []v1.NodeSelectorRequirement{{
									Key:      "type",
									Operator: v1.NodeSelectorOpExists,
								}},
							}},
						},
					},
				}
				comps.typha.Spec.Template.Spec.Affinity = aff
				i.Spec.KubernetesProvider = operatorv1.ProviderAKS
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(*i.Spec.TyphaDeployment.Spec.Template.Spec.Affinity).To(Equal(*aff))
			})
		})

		Describe("kube-controllers", func() {
			It("should not error for nil nodeSelector", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = nil
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
			It("should add nodeSelector to the installation", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "bar"}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should remove linux OS nodeSelector terms", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = map[string]string{
					"beta.kubernetes.io/os": "linux",
					"foo":                   "bar",
					"kubernetes.io/os":      "linux",
				}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should not error if the same nodeSelector is in the resource and the installation", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = map[string]string{
					"foo":              "bar",
					"kubernetes.io/os": "linux",
				}
				// We remove the OS nodeSelector key/value pair so they are equal
				helpers.EnsureKubeControllersNodeSelectorNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector = map[string]string{
					"foo": "bar",
				}

				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			})
			It("should error if the nodeSelector key exists in the resource and the installation but values differ", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "bar"}
				helpers.EnsureKubeControllersNodeSelectorNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "baz"}
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should error if the nodeSelector exists in the installation but not the resource", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = map[string]string{}
				helpers.EnsureKubeControllersNodeSelectorNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector = map[string]string{"foo": "baz"}
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should not error for empty affinity", func() {
				comps.kubeControllers.Spec.Template.Spec.Affinity = &v1.Affinity{}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity).To(Equal(comps.node.Spec.Template.Spec.Affinity))
			})
			It("should not error for nil affinity", func() {
				comps.kubeControllers.Spec.Template.Spec.Affinity = nil
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.CalicoKubeControllersDeployment).To(BeNil())
			})
			It("should not error if the same affinity is in the resource and the installation", func() {
				comps.kubeControllers.Spec.Template.Spec.Affinity = aff1
				helpers.EnsureKubeControllersPodSpecNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity = aff1

				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(*i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity).To(Equal(*aff1))
			})
			It("should error if the affinity exists in the resource and the installation but values differ", func() {
				comps.kubeControllers.Spec.Template.Spec.Affinity = aff1
				helpers.EnsureKubeControllersPodSpecNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity = aff2

				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should error if the affinity exists in the installation but not the resource", func() {
				helpers.EnsureKubeControllersPodSpecNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity = aff1
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
		})
	})

	Context("minReadySeconds", func() {
		var zero int32 = 0
		var one int32 = 1
		var two int32 = 2

		DescribeTable("calico-node", func(compMinReadySeconds *int32, installMinReadySeconds *int32, expectErr bool) {
			if compMinReadySeconds != nil {
				comps.node.Spec.MinReadySeconds = *compMinReadySeconds
			}
			if installMinReadySeconds != nil {
				helpers.EnsureCalicoNodeSpecNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.MinReadySeconds = installMinReadySeconds
			}

			err := handleCore(&comps, i)
			if expectErr {
				Expect(err).To(HaveOccurred())
			} else {
				// Only set minReadySeconds on the install if the value is not the default.
				if compMinReadySeconds != nil && *compMinReadySeconds != 0 {
					Expect(i.Spec.CalicoNodeDaemonSet.Spec.MinReadySeconds).ToNot(BeNil())
					Expect(*i.Spec.CalicoNodeDaemonSet.Spec.MinReadySeconds).To(Equal(*compMinReadySeconds))
				}
			}
		},
			Entry("only component is 0", &zero, nil, false),
			Entry("only component is non-zero", &one, nil, false),
			Entry("only install is 0", nil, &zero, false),
			Entry("only install is non-zero", nil, &one, true),
			Entry("both component and install are 0", &zero, &zero, false),
			Entry("both component and install are both non-zero and equal", &one, &one, false),
			Entry("both component and install are both non-zero and not equal", &one, &two, true),
			Entry("both component and install are both non-zero and not equal", &two, &one, true),
		)
		DescribeTable("typha", func(compMinReadySeconds *int32, installMinReadySeconds *int32, expectErr bool) {
			if compMinReadySeconds != nil {
				comps.typha.Spec.MinReadySeconds = *compMinReadySeconds
			}
			if installMinReadySeconds != nil {
				helpers.EnsureTyphaPodSpecNotNil(i)
				i.Spec.TyphaDeployment.Spec.MinReadySeconds = installMinReadySeconds
			}

			err := handleCore(&comps, i)
			if expectErr {
				Expect(err).To(HaveOccurred())
			} else {
				// Only set minReadySeconds on the install if the value is not the default.
				if compMinReadySeconds != nil && *compMinReadySeconds != 0 {
					Expect(i.Spec.TyphaDeployment.Spec.MinReadySeconds).ToNot(BeNil())
					Expect(*i.Spec.TyphaDeployment.Spec.MinReadySeconds).To(Equal(*compMinReadySeconds))
				}
			}
		},
			Entry("only component is 0", &zero, nil, false),
			Entry("only component is non-zero", &one, nil, false),
			Entry("only install is 0", nil, &zero, false),
			Entry("only install is non-zero", nil, &one, true),
			Entry("both component and install are 0", &zero, &zero, false),
			Entry("both component and install are both non-zero and equal", &one, &one, false),
			Entry("both component and install are both non-zero and not equal", &one, &two, true),
			Entry("both component and install are both non-zero and not equal", &two, &one, true),
		)
		DescribeTable("kubecontrollers", func(compMinReadySeconds *int32, installMinReadySeconds *int32, expectErr bool) {
			if compMinReadySeconds != nil {
				comps.kubeControllers.Spec.MinReadySeconds = *compMinReadySeconds
			}
			if installMinReadySeconds != nil {
				helpers.EnsureKubeControllersPodSpecNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.MinReadySeconds = installMinReadySeconds
			}

			err := handleCore(&comps, i)
			if expectErr {
				Expect(err).To(HaveOccurred())
			} else {
				// Only set minReadySeconds on the install if the value is not the default.
				if compMinReadySeconds != nil && *compMinReadySeconds != 0 {
					Expect(i.Spec.CalicoKubeControllersDeployment.Spec.MinReadySeconds).ToNot(BeNil())
					Expect(*i.Spec.CalicoKubeControllersDeployment.Spec.MinReadySeconds).To(Equal(*compMinReadySeconds))
				}
			}
		},
			Entry("only component is 0", &zero, nil, false),
			Entry("only component is non-zero", &one, nil, false),
			Entry("only install is 0", nil, &zero, false),
			Entry("only install is non-zero", nil, &one, true),
			Entry("both component and install are 0", &zero, &zero, false),
			Entry("both component and install are both non-zero and equal", &one, &one, false),
			Entry("both component and install are both non-zero and not equal", &one, &two, true),
			Entry("both component and install are both non-zero and not equal", &two, &one, true),
		)
	})

	Context("tolerations", func() {
		var empty = []corev1.Toleration{}
		var t1 corev1.Toleration = corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		var tolerateCriticalAddonsOnly = corev1.Toleration{
			Key:      "CriticalAddonsOnly",
			Operator: corev1.TolerationOpExists,
		}
		var tolerateNoSchedule = corev1.Toleration{
			Effect:   corev1.TaintEffectNoSchedule,
			Operator: corev1.TolerationOpExists,
		}
		var tolerateNoExecute = corev1.Toleration{
			Effect:   corev1.TaintEffectNoExecute,
			Operator: corev1.TolerationOpExists,
		}
		// default node and typha tolerations
		var tolerateAll = []corev1.Toleration{
			tolerateCriticalAddonsOnly,
			tolerateNoSchedule,
			tolerateNoExecute,
		}
		var tolerateMaster = corev1.Toleration{
			Key:    "node-role.kubernetes.io/master",
			Effect: corev1.TaintEffectNoSchedule,
		}
		// default kube-controllers tolerations
		var kubeControllersTolerations = []corev1.Toleration{
			tolerateMaster,
			tolerateCriticalAddonsOnly,
		}

		DescribeTable("calico-node", func(compTols []corev1.Toleration, installTols []corev1.Toleration, expectedInstallTols []corev1.Toleration, isValid bool) {
			comps.node.Spec.Template.Spec.Tolerations = compTols

			if installTols != nil {
				helpers.EnsureCalicoNodePodSpecNotNil(i)
				i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations = installTols
			}

			err := handleCore(&comps, i)
			if isValid {
				if expectedInstallTols == nil {
					Expect(i.Spec.CalicoNodeDaemonSet).To(BeNil())
				} else {
					Expect(i.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations).To(Equal(expectedInstallTols))
				}
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			// empty component tolerations
			Entry("ok if component has empty tolerations and install has empty tolerations", empty, empty, empty, true),
			Entry("error if component has empty tolerations and install has nil tolerations", empty, nil, nil, false),
			Entry("error if component has empty tolerations and install has tolerations", empty, []corev1.Toleration{t1}, nil, false),
			// nil component tolerations
			Entry("ok if component has nil tolerations and install has empty tolerations", nil, empty, empty, true),
			Entry("error if component has nil tolerations and install has nil tolerations", nil, nil, nil, false),
			Entry("error if component has nil tolerations and install has tolerations", nil, []corev1.Toleration{t1}, nil, false),
			Entry("error if component has nil tolerations and install has tolerations", nil, []corev1.Toleration{t1}, nil, false),
			// all default component tolerations
			Entry("ok if component has all the default tolerations and install has nil tolerations", tolerateAll, nil, nil, true),
			Entry("ok if component has all the default tolerations and install has the same tolerations", tolerateAll, tolerateAll, tolerateAll, true),
			Entry("error if component has all default tolerations and install has empty tolerations", tolerateAll, empty, nil, false),
			// component tolerations
			Entry("ok if component has tolerations and install has nil tolerations", []corev1.Toleration{t1}, nil, []corev1.Toleration{t1}, true),
			Entry("error if component has tolerations and install has empty tolerations", []corev1.Toleration{t1}, empty, nil, false),
			Entry("error if component has tolerations and install has different tolerations", []corev1.Toleration{tolerateNoExecute, t1}, []corev1.Toleration{t1}, nil, false),
			Entry("ok if component has tolerations and install has same tolerations", []corev1.Toleration{t1}, []corev1.Toleration{t1}, []corev1.Toleration{t1}, true),
			Entry("ok if component has default and custom tolerations and install has the same tolerations", append(tolerateAll, t1), append(tolerateAll, t1), append(tolerateAll, t1), true),
		)

		DescribeTable("typha", func(compTols []corev1.Toleration, installTols []corev1.Toleration, expectedInstallTols []corev1.Toleration, isValid bool) {
			comps.typha.Spec.Template.Spec.Tolerations = compTols

			if installTols != nil {
				helpers.EnsureTyphaPodSpecNotNil(i)
				i.Spec.TyphaDeployment.Spec.Template.Spec.Tolerations = installTols
			}

			err := handleCore(&comps, i)
			if isValid {
				if expectedInstallTols == nil {
					Expect(i.Spec.TyphaDeployment).To(BeNil())
				} else {
					Expect(i.Spec.TyphaDeployment.Spec.Template.Spec.Tolerations).To(Equal(expectedInstallTols))
				}
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			// empty component tolerations
			Entry("ok if component has empty tolerations and install has empty tolerations", empty, empty, empty, true),
			Entry("error if component has empty tolerations and install has nil tolerations", empty, nil, nil, false),
			Entry("error if component has empty tolerations and install has tolerations", empty, []corev1.Toleration{t1}, nil, false),
			// nil component tolerations
			Entry("ok if component has nil tolerations and install has empty tolerations", nil, empty, empty, true),
			Entry("error if component has nil tolerations and install has nil tolerations", nil, nil, nil, false),
			Entry("error if component has nil tolerations and install has tolerations", nil, []corev1.Toleration{t1}, nil, false),
			Entry("error if component has nil tolerations and install has tolerations", nil, []corev1.Toleration{t1}, nil, false),
			// all default component tolerations
			Entry("ok if component has all the default tolerations and install has nil tolerations", tolerateAll, nil, nil, true),
			Entry("ok if component has all the default tolerations and install has the same tolerations", tolerateAll, tolerateAll, tolerateAll, true),
			Entry("error if component has all default tolerations and install has empty tolerations", tolerateAll, empty, nil, false),
			// component tolerations
			Entry("ok if component has tolerations and install has nil tolerations", []corev1.Toleration{t1}, nil, []corev1.Toleration{t1}, true),
			Entry("error if component has tolerations and install has empty tolerations", []corev1.Toleration{t1}, empty, nil, false),
			Entry("error if component has tolerations and install has different tolerations", []corev1.Toleration{tolerateNoExecute, t1}, []corev1.Toleration{t1}, nil, false),
			Entry("ok if component has tolerations and install has same tolerations", []corev1.Toleration{t1}, []corev1.Toleration{t1}, []corev1.Toleration{t1}, true),
			Entry("ok if component has default and custom tolerations and install has the same tolerations", append(tolerateAll, t1), append(tolerateAll, t1), append(tolerateAll, t1), true),
		)
		DescribeTable("kube-controllers", func(compTols []corev1.Toleration, installTols []corev1.Toleration, expectedInstallTols []corev1.Toleration, isValid bool) {
			comps.kubeControllers.Spec.Template.Spec.Tolerations = compTols

			if installTols != nil {
				helpers.EnsureKubeControllersPodSpecNotNil(i)
				i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Tolerations = installTols
			}

			err := handleCore(&comps, i)
			if isValid {
				if expectedInstallTols == nil {
					Expect(i.Spec.CalicoKubeControllersDeployment).To(BeNil())
				} else {
					Expect(i.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Tolerations).To(Equal(expectedInstallTols))
				}
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			// empty component tolerations
			Entry("ok if component has empty tolerations and install has empty tolerations", empty, empty, empty, true),
			Entry("error if component has empty tolerations and install has nil tolerations", empty, nil, nil, false),
			Entry("error if component has empty tolerations and install has tolerations", empty, []corev1.Toleration{t1}, nil, false),
			// nil component tolerations
			Entry("ok if component has nil tolerations and install has empty tolerations", nil, empty, empty, true),
			Entry("error if component has nil tolerations and install has nil tolerations", nil, nil, nil, false),
			Entry("error if component has nil tolerations and install has tolerations", nil, []corev1.Toleration{t1}, nil, false),
			Entry("error if component has nil tolerations and install has tolerations", nil, []corev1.Toleration{t1}, nil, false),
			// all default component tolerations - kubecontrollers has different default tolerations
			Entry("ok if component has all the default tolerations and install has nil tolerations", kubeControllersTolerations, nil, nil, true),
			Entry("ok if component has all the default tolerations and install has the same tolerations", kubeControllersTolerations, kubeControllersTolerations, kubeControllersTolerations, true),
			Entry("error if component has all default tolerations and install has empty tolerations", kubeControllersTolerations, empty, nil, false),
			// component tolerations
			Entry("ok if component has tolerations and install has nil tolerations", []corev1.Toleration{t1}, nil, []corev1.Toleration{t1}, true),
			Entry("error if component has tolerations and install has empty tolerations", []corev1.Toleration{t1}, empty, nil, false),
			Entry("error if component has tolerations and install has different tolerations", []corev1.Toleration{tolerateNoExecute, t1}, []corev1.Toleration{t1}, nil, false),
			Entry("ok if component has tolerations and install has same tolerations", []corev1.Toleration{t1}, []corev1.Toleration{t1}, []corev1.Toleration{t1}, true),
			Entry("ok if component has some default and custom tolerations and install has the same tolerations", append(tolerateAll, t1), append(tolerateAll, t1), append(tolerateAll, t1), true),
		)

	})

	Context("node update strategy", func() {
		It("should not set updateStrategy if none is set", func() {
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.NodeUpdateStrategy).To(Equal(appsv1.DaemonSetUpdateStrategy{}))
		})
		It("should carry forward updateStrategy", func() {
			twelve := intstr.FromInt(12)
			updateStrategy := appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.OnDeleteDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &twelve,
				},
			}
			comps.node.Spec.UpdateStrategy = updateStrategy
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.NodeUpdateStrategy).To(Equal(updateStrategy))
		})
	})

	Context("flexvol", func() {
		It("should not be set by default", func() {
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.FlexVolumePath).To(Equal("None"))
		})
		It("should carry forward flexvolumepath", func() {
			hostPathDirectoryOrCreate := v1.HostPathDirectoryOrCreate
			path := "/foo/bar/"
			comps.node.Spec.Template.Spec.Volumes = append(comps.node.Spec.Template.Spec.Volumes, v1.Volume{
				Name: "flexvol-driver-host",
				VolumeSource: v1.VolumeSource{
					HostPath: &v1.HostPathVolumeSource{
						Path: path,
						Type: &hostPathDirectoryOrCreate,
					},
				},
			})
			comps.node.Spec.Template.Spec.InitContainers = append(comps.node.Spec.Template.Spec.InitContainers, v1.Container{
				Name: "flexvol-driver",
			})

			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.FlexVolumePath).To(Equal(path))
		})
	})

	Context("nodename", func() {
		// AssertNodeName parameterizes the tests for Nodename so that they can be run
		// on the install-cni container and the calico/node container, both of which use
		// a different env var name.
		// the 'setEnvVars' function is used to update the correct container's env vars
		// for the given test.
		AssertNodeName := func(nodeNameVarName string, setEnvVars func([]v1.EnvVar)) {
			It("should not throw an error if set to noderef", func() {
				setEnvVars([]v1.EnvVar{{
					Name: nodeNameVarName,
					ValueFrom: &v1.EnvVarSource{
						FieldRef: &v1.ObjectFieldSelector{
							FieldPath: "spec.nodeName",
						},
					},
				}})
				Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			})
			It("should throw an error if set to a different fieldPath", func() {
				setEnvVars([]v1.EnvVar{{
					Name: nodeNameVarName,
					ValueFrom: &v1.EnvVarSource{
						FieldRef: &v1.ObjectFieldSelector{
							FieldPath: "metadata.name",
						},
					},
				}})
				Expect(handleCore(&comps, i)).To(HaveOccurred())
			})
			It("should throw an error if hardcoded to a value", func() {
				setEnvVars([]v1.EnvVar{{
					Name:  nodeNameVarName,
					Value: "foobar",
				}})
				Expect(handleCore(&comps, i)).To(HaveOccurred())
			})
		}

		It("should not throw an error if no nodenames are set", func() {
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
		})

		It("should not throw an error if both are set correctly", func() {
			comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name: "NODENAME",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			}}
			comps.node.Spec.Template.Spec.InitContainers[0].Env = []v1.EnvVar{{
				Name: "KUBERNETES_NODE_NAME",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			}}
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
		})

		Context("on the calico/node container", func() {
			AssertNodeName("NODENAME", func(envVars []v1.EnvVar) {
				comps.node.Spec.Template.Spec.Containers[0].Env = envVars
			})
		})
		Context("on the install-cni container", func() {
			AssertNodeName("KUBERNETES_NODE_NAME", func(envVars []v1.EnvVar) {
				comps.node.Spec.Template.Spec.InitContainers[0].Env = envVars
			})
		})
	})

	Context("cni", func() {
		It("should not raise an error if CNI_CONF_NAME is 10-calico.conflist", func() {
			comps.node.Spec.Template.Spec.InitContainers[0].Env = []v1.EnvVar{{
				Name:  "CNI_CONF_NAME",
				Value: "10-calico.conflist",
			}}
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
		})
		It("should raise error if CNI_CONF_NAME isn't 10-calico.conflist", func() {
			comps.node.Spec.Template.Spec.InitContainers[0].Env = []v1.EnvVar{{
				Name:  "CNI_CONF_NAME",
				Value: "2-calico.conflist",
			}}
			Expect(handleCore(&comps, i)).To(HaveOccurred())
		})
	})
	Context("kube-controllers", func() {
		Context("ENABLED_CONTROLLERS", func() {
			It("should not error if ENABLED_CONTROLLERS is expected value", func() {
				comps.kubeControllers.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
					Name:  "ENABLED_CONTROLLERS",
					Value: "node",
				}}
				Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			})
			It("should error if ENABLED_CONTROLLERS is not expected value", func() {
				comps.kubeControllers.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
					Name:  "ENABLED_CONTROLLERS",
					Value: "hep",
				}}
				Expect(handleCore(&comps, i)).To(HaveOccurred())
			})
		})
		Context("AUTO_HOST_ENDPOINTS", func() {
			It("should not error if AUTO_HOST_ENDPOINTS is expected value", func() {
				comps.kubeControllers.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
					Name:  "AUTO_HOST_ENDPOINTS",
					Value: "disabled",
				}}
				Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			})
			It("should error if AUTO_HOST_ENDPOINTS is not expected value", func() {
				comps.kubeControllers.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
					Name:  "AUTO_HOST_ENDPOINTS",
					Value: "enabled",
				}}
				Expect(handleCore(&comps, i)).To(HaveOccurred())
			})
		})
	})
	Context("felix prometheus metrics", func() {
		It("with metrics enabled the default port is used", func() {
			comps.node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "FELIX_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}}
			Expect(handleFelixNodeMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(*i.Spec.NodeMetricsPort).To(Equal(int32(9091)))
		})
		It("defaults prometheus off when no prometheus environment variables set", func() {

			Expect(handleFelixNodeMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.NodeMetricsPort).To(BeNil())
		})
		It("with metrics enabled the default port is used", func() {
			comps.node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "FELIX_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}}

			Expect(handleFelixNodeMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(*i.Spec.NodeMetricsPort).To(Equal(int32(9091)))
		})
		It("with metrics port env var only, metrics are still disabled", func() {
			comps.node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "FELIX_PROMETHEUSMETRICSPORT",
				Value: "5555",
			}}

			Expect(handleFelixNodeMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.NodeMetricsPort).To(BeNil())
		})
		It("with metrics port and enabled is reflected in installation", func() {
			comps.node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "FELIX_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}, {
				Name:  "FELIX_PROMETHEUSMETRICSPORT",
				Value: "7777",
			}}

			Expect(handleFelixNodeMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(*i.Spec.NodeMetricsPort).To(Equal(int32(7777)))
		})
	})
})
