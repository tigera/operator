package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Elasticsearch rendering tests", func() {
	var logStorage *operator.LogStorage
	BeforeEach(func() {
		// Initialize a default logStorage to use. Each test can override this to its
		// desired configuration.
		logStorage = &operator.LogStorage{
			Spec: operator.LogStorageSpec{
				Certificate: &corev1.SecretReference{
					Name: "tigera-es-config",
				},
				Nodes: &operator.Nodes{
					Count: 1,
					StorageClass: nil,
					ResourceRequirements: nil,
				},
				Indices: &operator.Indices{
					Replicas: 1,
				},
			},
			Status: operator.LogStorageStatus{
				State: "",
			},
		}

	})

	It("should render an elasticsearchComponent", func() {
		component, err := render.Elasticsearch(*logStorage, false)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(3))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "tigera-elasticsearch", "", "", "", "")
		ExpectResource(resources[2], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})

	It("should render an elasticsearchComponent with openShift", func() {
		component, err := render.Elasticsearch(*logStorage, true)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(3))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "tigera-elasticsearch", "", "", "", "")
		ExpectResource(resources[2], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})

	It("should render an elasticsearchComponent without assigning esDefaultStorageClass", func() {
		logStorage.Spec.Nodes.StorageClass = &corev1.ObjectReference{
			Name: "tigera-elasticsearch",
		}
		component, err := render.Elasticsearch(*logStorage, false)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(2))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})

	It("should render an elasticsearchComponent while logStorage.Spec.Certificate == nil", func() {
		logStorage.Spec.Certificate = nil
		component, err := render.Elasticsearch(*logStorage, false)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(3))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "tigera-elasticsearch", "", "", "", "")
		ExpectResource(resources[2], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})
})
