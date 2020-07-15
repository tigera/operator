package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

var _ = Describe("core handler", func() {
	var (
		comps = emptyComponents()
		i     = &Installation{}
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &Installation{}
	})
	Context("resource migration", func() {
		It("should not migrate resource requirements if none are set", func() {
			err := handleCore(&comps, i)
			Expect(err).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(BeEmpty())
		})

		It("should migrate resources from calico-node if they are set", func() {
			comps.node.Spec.Template.Spec.Containers[0].Resources = v1.ResourceRequirements{
				Limits: v1.ResourceList{
					v1.ResourceCPU:    resource.MustParse("500m"),
					v1.ResourceMemory: resource.MustParse("500Mi"),
				},
				Requests: v1.ResourceList{
					v1.ResourceCPU:    resource.MustParse("250m"),
					v1.ResourceMemory: resource.MustParse("64Mi"),
				},
			}

			Expect(handleCore(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.ComponentResources).To(ConsistOf(&operatorv1.ComponentResource{
				ComponentName: operatorv1.ComponentNameNode,
				ResourceRequirements: &v1.ResourceRequirements{
					Requests: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("250m"),
						v1.ResourceMemory: resource.MustParse("64Mi"),
					},
					Limits: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("500m"),
						v1.ResourceMemory: resource.MustParse("500Mi"),
					},
				},
			}))
		})
	})
})

// emptyComponents is a convenience function for initializing a
// components object which meets basic validation requirements.
func emptyComponents() components {
	return components{
		node: CheckedDaemonSet{
			*emptyNodeSpec(),
			make(map[string]checkedFields),
		},
	}
}

func getComponentResources(component operatorv1.ComponentName) *operatorv1.ComponentResource {
	return nil
}
