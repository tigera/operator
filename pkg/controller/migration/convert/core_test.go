package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

var _ = Describe("core handler", func() {
	var (
		comps = emptyComponents()
		i     = &Installation{}
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &Installation{
			Installation: &operatorv1.Installation{},
			CNIConfig:    "",
			FelixEnvVars: []v1.EnvVar{},
		}
	})
	Context("resource migration", func() {
		It("should not migrate resource requirements if none are set", func() {
			err := handleCore(&comps, i)
			Expect(err).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(BeEmpty())
		})

		var rqs = v1.ResourceRequirements{
			Limits: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("500m"),
				v1.ResourceMemory: resource.MustParse("500Mi"),
			},
			Requests: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("250m"),
				v1.ResourceMemory: resource.MustParse("64Mi"),
			},
		}

		It("should migrate resources from calico-node if they are set", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = rqs
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(ConsistOf(&operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameNode,
				ResourceRequirements: &rqs,
			}))
		})

		It("should migrate resources from kube-controllers if they are set", func() {
			comps.kubeControllers.Spec.Template.Spec.Containers[0].Resources = rqs
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(ConsistOf(&operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameKubeControllers,
				ResourceRequirements: &rqs,
			}))
		})

		It("should migrate resources from typha if they are set", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Resources = rqs
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(ConsistOf(&operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameTypha,
				ResourceRequirements: &rqs,
			}))
		})
		It("should migrate resources from all 3 components", func() {
			rqs = v1.ResourceRequirements{
				Limits: v1.ResourceList{
					v1.ResourceCPU: resource.MustParse("500m"),
				},
			}
			expectedCompRsrc := []*operatorv1.ComponentResource{&operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameNode,
				ResourceRequirements: rqs.DeepCopy(),
			}}
			comps.node.Spec.Template.Spec.Containers[0].Resources = *rqs.DeepCopy()
			rqs.Limits[v1.ResourceCPU] = resource.MustParse("400m")
			expectedCompRsrc = append(expectedCompRsrc, &operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameKubeControllers,
				ResourceRequirements: rqs.DeepCopy(),
			})
			comps.kubeControllers.Spec.Template.Spec.Containers[0].Resources = *rqs.DeepCopy()
			rqs.Limits[v1.ResourceCPU] = resource.MustParse("300m")
			expectedCompRsrc = append(expectedCompRsrc, &operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameTypha,
				ResourceRequirements: rqs.DeepCopy(),
			})
			comps.typha.Spec.Template.Spec.Containers[0].Resources = *rqs.DeepCopy()
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(ConsistOf(expectedCompRsrc))
		})

		It("should not add a duplicate resources when already set", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = rqs
			i.Spec.ComponentResources = append(i.Spec.ComponentResources, &operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameNode,
				ResourceRequirements: &rqs,
			})
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(HaveLen(1))
		})
	})

	Context("nodeSelector", func() {
		TestNodeSelectors := func(f func(map[string]string)) {
			It("should error for unexpected nodeSelectors", func() {
				f(map[string]string{"foo": "bar"})
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should not error for beta.kubernetes.io/os=linux nodeSelector", func() {
				f(map[string]string{"beta.kubernetes.io/os": "linux"})
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not error for kubernetes.io/os=linux", func() {
				f(map[string]string{"kubernetes.io/os": "linux"})
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
			It("should error for other kubernetes.io/os nodeSelectors", func() {
				f(map[string]string{"kubernetes.io/os": "windows"})
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should still error even if a valid and invalid nodeselector are set", func() {
				f(map[string]string{
					"kubernetes.io/os": "linux",
					"foo":              "bar",
				})
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
			It("should not panic for nil nodeselectors", func() {
				f(nil)
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
		}
		Describe("calico-node", func() {
			TestNodeSelectors(func(nodeSelectors map[string]string) {
				comps.node.Spec.Template.Spec.NodeSelector = nodeSelectors
			})

			It("should not error if the migration nodeSelector is set", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{
					"projectcalico.org/operator-node-migration": "pre-operator",
				}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
			})
			It("should error if a nodeSelector is set alongside the migration nodeSelector", func() {
				comps.node.Spec.Template.Spec.NodeSelector = map[string]string{
					"foo": "bar",
					"projectcalico.org/operator-node-migration": "pre-operator",
				}
				Expect(handleNodeSelectors(&comps, i)).To(HaveOccurred())
			})
		})
		Describe("typha", func() {
			TestNodeSelectors(func(nodeSelectors map[string]string) {
				comps.typha.Spec.Template.Spec.NodeSelector = nodeSelectors
			})
		})

		// kube-controllers has a configurable nodeSelector which should
		// be carried forward
		Context("kube-controllers", func() {
			It("should carry forward custom nodeSelector on kube-controllers, but drop the os nodeselector", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = map[string]string{
					"kubernetes.io/os": "linux",
					"foo":              "bar",
				}
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.ControlPlaneNodeSelector).To(Equal(map[string]string{"foo": "bar"}))
			})

			It("should carry forward other kubernetes.io/os nodeSelectors", func() {
				comps.kubeControllers.Spec.Template.Spec.NodeSelector = map[string]string{
					"kubernetes.io/os": "windows",
				}
				// we don't expect an error to occur here, because the final validation handler should catch this.
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.ControlPlaneNodeSelector).To(Equal(map[string]string{"kubernetes.io/os": "windows"}))
			})
			It("should not set nodeSelector if none is set", func() {
				Expect(handleNodeSelectors(&comps, i)).ToNot(HaveOccurred())
				Expect(i.Spec.ControlPlaneNodeSelector).To(BeNil())
			})
		})
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

		Context("tolerations", func() {
			// TestTolerations parameterizes the tests for tolerations to that they can be run
			// on node, kubeControllers, and typha. These tests assume that the emptyComponents
			// function initializes all components with the expected, valid tolerations (which it does).
			// the first parameter is the existing tolerations, so that they can be adjusted.
			// the second parameter is a function which updates the tolerations of the desired component.
			TestTolerations := func(existingTolerations []v1.Toleration, setTolerations func([]v1.Toleration)) {
				It("should not error if only expected tolerations are set", func() {
					Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
				})
				It("should not error if no tolerations set", func() {
					setTolerations([]v1.Toleration{})
					Expect(handleCore(&comps, i)).NotTo(HaveOccurred())
				})
				It("should not error if missing just one toleration", func() {
					setTolerations(existingTolerations[0 : len(existingTolerations)-1])
					Expect(handleCore(&comps, i)).NotTo(HaveOccurred())
				})
				It("should not error if additional toleration exists", func() {
					setTolerations(append(existingTolerations, v1.Toleration{
						Key:    "foo",
						Effect: "bar",
					}))
					Expect(handleCore(&comps, i)).NotTo(HaveOccurred())
				})
			}
			Describe("calico-node", func() {
				TestTolerations(comps.node.Spec.Template.Spec.Tolerations, func(t []v1.Toleration) {
					comps.node.Spec.Template.Spec.Tolerations = t
				})
			})
			Describe("kube-controllers", func() {
				TestTolerations(comps.kubeControllers.Spec.Template.Spec.Tolerations, func(t []v1.Toleration) {
					comps.kubeControllers.Spec.Template.Spec.Tolerations = t
				})
			})
			Describe("typha", func() {
				TestTolerations(comps.typha.Spec.Template.Spec.Tolerations, func(t []v1.Toleration) {
					comps.typha.Spec.Template.Spec.Tolerations = t
				})
			})
		})
	})

	Context("annotations", func() {
		ExpectAnnotations := func(updateAnnotations func(map[string]string)) {
			It("should not error for no annotations", func() {
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should error for unexpected annotations", func() {
				updateAnnotations(map[string]string{"foo": "bar"})
				Expect(handleAnnotations(&comps, i)).To(HaveOccurred())
			})
			It("should not error for acceptable annotations", func() {
				updateAnnotations(map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{}"})
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
			It("should not panic for nil annotations", func() {
				updateAnnotations(nil)
				Expect(handleAnnotations(&comps, i)).ToNot(HaveOccurred())
			})
		}
		Context("calico-node", func() {
			ExpectAnnotations(func(annotations map[string]string) {
				comps.node.Annotations = annotations
			})
			ExpectAnnotations(func(annotations map[string]string) {
				comps.node.Spec.Template.Annotations = annotations
			})
		})
		Context("kube-controllers", func() {
			ExpectAnnotations(func(annotations map[string]string) {
				comps.kubeControllers.Annotations = annotations
			})
			ExpectAnnotations(func(annotations map[string]string) {
				comps.kubeControllers.Spec.Template.Annotations = annotations
			})
		})
		Context("typha", func() {
			ExpectAnnotations(func(annotations map[string]string) {
				comps.typha.Annotations = annotations
			})
			ExpectAnnotations(func(annotations map[string]string) {
				comps.typha.Spec.Template.Annotations = annotations
			})
			It("should not error if typha's safe-to-evict annotation is set", func() {
				comps.typha.Spec.Template.Annotations = map[string]string{
					"cluster-autoscaler.kubernetes.io/safe-to-evict": "true",
				}
				Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
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
})
