package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Elasticsearch rendering tests", func() {
	var logStorage *operator.LogStorage
	BeforeEach(func() {
		// Initialize a default logStorage to use. Each test can override this to its
		// desired configuration.
		logStorage = &operator.LogStorage{
			Spec: operator.LogStorageSpec{
				Nodes: &operator.Nodes{
					Count:                1,
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
		component, err := render.Elasticsearch(logStorage, nil, false, "docker.elastic.co/eck/")
		resources := component.Objects()
		Expect(len(resources)).To(Equal(10))
		Expect(err).NotTo(HaveOccurred())

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-eck-operator", "", "", "v1", "Namespace"},
			{"webhook-server-secret", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"tigera-elasticsearch", "", "", "v1", "Namespace"},
			{"tigera-secure-elasticsearch-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-elasticsearch-cert", "tigera-elasticsearch", "", "v1", "Secret"},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
		}

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render an elasticsearchComponent with openShift", func() {
		component, err := render.Elasticsearch(logStorage, nil, true, "docker.elastic.co/eck/")
		resources := component.Objects()
		Expect(len(resources)).To(Equal(10))
		Expect(err).NotTo(HaveOccurred())

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-eck-operator", "", "", "v1", "Namespace"},
			{"webhook-server-secret", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"tigera-elasticsearch", "", "", "v1", "Namespace"},
			{"tigera-secure-elasticsearch-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-elasticsearch-cert", "tigera-elasticsearch", "", "v1", "Secret"},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
		}

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})
})
