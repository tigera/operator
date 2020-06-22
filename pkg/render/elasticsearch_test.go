package render_test

import (
	esalpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/elasticsearch/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Elasticsearch rendering tests", func() {
	var logStorage *operator.LogStorage
	replicas := int32(1)
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
					Replicas: &replicas,
				},
			},
			Status: operator.LogStorageStatus{
				State: "",
			},
		}
	})

	It("should render an elasticsearchComponent", func() {
		component, err := render.Elasticsearch(logStorage, nil, nil, false, nil, operator.ProviderNone,
			&operator.Installation{Spec: operator.InstallationSpec{Registry: "docker.elastic.co/eck/"}},
		)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(13))
		Expect(err).NotTo(HaveOccurred())

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-eck-operator", "", "", "v1", "Namespace"},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"tigera-elasticsearch", "", "", "v1", "Namespace"},
			{"tigera-secure-elasticsearch-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-elasticsearch-cert", "tigera-elasticsearch", "", "v1", "Secret"},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render pull secrets", func() {
		component, err := render.Elasticsearch(logStorage, nil, nil, false,
			[]*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret"}}}, operator.ProviderNone,
			&operator.Installation{Spec: operator.InstallationSpec{Registry: "docker.elastic.co/eck/"}},
		)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(16))
		Expect(err).NotTo(HaveOccurred())

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-eck-operator", "", "", "v1", "Namespace"},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"pull-secret", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"tigera-elasticsearch", "", "", "v1", "Namespace"},
			{"pull-secret", "tigera-elasticsearch", "", "", ""},
			{"tigera-secure-elasticsearch-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-elasticsearch-cert", "tigera-elasticsearch", "", "v1", "Secret"},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"pull-secret", "tigera-kibana", "", "", ""},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render an elasticsearchComponent with openShift", func() {
		component, err := render.Elasticsearch(logStorage, nil, nil, false, nil, operator.ProviderOpenShift,
			&operator.Installation{Spec: operator.InstallationSpec{Registry: "docker.elastic.co/eck/"}},
		)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(13))
		Expect(err).NotTo(HaveOccurred())

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-eck-operator", "", "", "v1", "Namespace"},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"tigera-elasticsearch", "", "", "v1", "Namespace"},
			{"tigera-secure-elasticsearch-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-elasticsearch-cert", "tigera-elasticsearch", "", "v1", "Secret"},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render an elasticsearchComponent with a webhook secret", func() {
		component, err := render.Elasticsearch(logStorage, nil, nil, true, nil, operator.ProviderOpenShift,
			&operator.Installation{Spec: operator.InstallationSpec{Registry: "docker.elastic.co/eck/"}},
		)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(14))
		Expect(err).NotTo(HaveOccurred())

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-eck-operator", "", "", "v1", "Namespace"},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"webhook-server-secret", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"tigera-elasticsearch", "", "", "v1", "Namespace"},
			{"tigera-secure-elasticsearch-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-elasticsearch-cert", "tigera-elasticsearch", "", "v1", "Secret"},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		resultES := resources[9].(*esalpha1.Elasticsearch).Spec.Nodes[0]
		// There are no node selectors in the LogStorage CR, so we expect no node selectors in the Elasticsearch CR.
		Expect(resultES.PodTemplate.Spec.NodeSelector).To(BeEmpty())
		Expect(resultES.PodTemplate.Spec.NodeSelector).To(BeEmpty())

		// Verify that the default container limist/requests are set.
		esContainer := resultES.PodTemplate.Spec.Containers[0]
		reqLimits := esContainer.Resources.Limits
		reqResources := esContainer.Resources.Requests

		Expect(reqLimits.Cpu().String()).To(Equal("1"))
		Expect(reqLimits.Memory().String()).To(Equal("4Gi"))
		Expect(reqResources.Cpu().String()).To(Equal("250m"))
		Expect(reqResources.Memory().String()).To(Equal("4Gi"))
		Expect(esContainer.Env[0].Value).To(Equal("-Xms1398101K -Xmx1398101K"))

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should not render Elasticsearch or Kibana cert secrets in the operator namespace when they are provided", func() {
		component, err := render.Elasticsearch(logStorage,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}}, false, nil, operator.ProviderOpenShift,
			&operator.Installation{Spec: operator.InstallationSpec{}},
		)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(11))
		Expect(err).NotTo(HaveOccurred())

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-eck-operator", "", "", "v1", "Namespace"},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"elastic-operator", "tigera-eck-operator", "", "", ""},
			{"tigera-elasticsearch", "", "", "v1", "Namespace"},
			{render.TigeraElasticsearchCertSecret, "tigera-elasticsearch", "", "", ""},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{render.TigeraKibanaCertSecret, "tigera-kibana", "", "", ""},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})
})
