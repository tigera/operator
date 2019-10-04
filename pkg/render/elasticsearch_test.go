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
		component, err := render.Elasticsearch(logStorage, false, "docker.elastic.co/eck/")
		resources := component.Objects()
		Expect(len(resources)).To(Equal(9))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-eck-operator", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "webhook-server-secret", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[2], "elastic-operator", "", "", "", "")
		ExpectResource(resources[3], "elastic-operator", "", "", "", "")
		ExpectResource(resources[4], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[5], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[6], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[7], "tigera-elasticsearch", "", "", "", "")
		ExpectResource(resources[8], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})

	It("should render an elasticsearchComponent with openShift", func() {
		component, err := render.Elasticsearch(logStorage, true, "docker.elastic.co/eck/")
		resources := component.Objects()
		Expect(len(resources)).To(Equal(9))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-eck-operator", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "webhook-server-secret", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[2], "elastic-operator", "", "", "", "")
		ExpectResource(resources[3], "elastic-operator", "", "", "", "")
		ExpectResource(resources[4], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[5], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[6], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[7], "tigera-elasticsearch", "", "", "", "")
		ExpectResource(resources[8], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})

	It("should render an elasticsearchComponent without assigning esDefaultStorageClass", func() {
		logStorage.Spec.Nodes.StorageClass = &corev1.ObjectReference{
			Name: "tigera-elasticsearch",
		}
		component, err := render.Elasticsearch(logStorage, false, "docker.elastic.co/eck/")
		resources := component.Objects()
		Expect(len(resources)).To(Equal(8))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-eck-operator", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "webhook-server-secret", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[2], "elastic-operator", "", "", "", "")
		ExpectResource(resources[3], "elastic-operator", "", "", "", "")
		ExpectResource(resources[4], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[5], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[6], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[7], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})

	It("should render an elasticsearchComponent while logStorage.Spec.Certificate == nil", func() {
		logStorage.Spec.Certificate = nil
		component, err := render.Elasticsearch(logStorage, false, "docker.elastic.co/eck/")
		resources := component.Objects()
		Expect(len(resources)).To(Equal(9))
		Expect(err).NotTo(HaveOccurred())
		ExpectResource(resources[0], "tigera-eck-operator", "", "", "v1", "Namespace")
		ExpectResource(resources[1], "webhook-server-secret", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[2], "elastic-operator", "", "", "", "")
		ExpectResource(resources[3], "elastic-operator", "", "", "", "")
		ExpectResource(resources[4], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[5], "elastic-operator", "tigera-eck-operator", "", "", "")
		ExpectResource(resources[6], "tigera-elasticsearch", "", "", "v1", "Namespace")
		ExpectResource(resources[7], "tigera-elasticsearch", "", "", "", "")
		ExpectResource(resources[8], "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch")
	})
})
