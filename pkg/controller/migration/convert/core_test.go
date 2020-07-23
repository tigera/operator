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
	})

	Context("nodeSelector", func() {
		It("should not set nodeSelector if none is set", func() {
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ControlPlaneNodeSelector).To(BeEmpty())
		})
		It("should carry forward nodeSelector", func() {
			nodeSelector := map[string]string{"foo": "bar"}
			comps.kubeControllers.Spec.Template.Spec.NodeSelector = nodeSelector
			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ControlPlaneNodeSelector).To(Equal(nodeSelector))
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
			Expect(i.Spec.FlexVolumePath).To(Equal(""))
		})
		It("should carry forward flexvolumepath", func() {
			hostPathDirectoryOrCreate := v1.HostPathDirectoryOrCreate
			path := "/foo/bar/"
			comps.node.Spec.Template.Spec.Volumes = []v1.Volume{{
				Name: "flexvol-driver-host",
				VolumeSource: v1.VolumeSource{
					HostPath: &v1.HostPathVolumeSource{
						Path: path,
						Type: &hostPathDirectoryOrCreate,
					},
				},
			}}
			comps.node.Spec.Template.Spec.InitContainers = append(comps.node.Spec.Template.Spec.InitContainers, v1.Container{
				Name: "flexvol-driver",
			})

			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.FlexVolumePath).To(Equal(path))
		})
	})
})
