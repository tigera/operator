// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	var esConfig *render.ElasticsearchClusterConfig
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
				DataNodeSelector: map[string]string{
					"label": "value",
				},
			},
			Status: operator.LogStorageStatus{
				State: "",
			},
		}

		esConfig = render.NewElasticsearchClusterConfig("cluster", 1, 5)
	})

	It("should render an elasticsearchComponent", func() {
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
			{render.ElasticsearchConfigMapName, render.OperatorNamespace(), "", "", ""},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		component, err := render.Elasticsearch(logStorage, esConfig, nil, nil, false, nil, operator.ProviderNone,
			&operator.Installation{Spec: operator.InstallationSpec{}},
		)
		Expect(err).NotTo(HaveOccurred())

		resources := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Verify that the node selectors are passed into the Elasticsearch pod spec.
		Expect(resources[9].(*esalpha1.Elasticsearch).Spec.Nodes[0].PodTemplate.Spec.NodeSelector["label"]).To(Equal("value"))

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render pull secrets", func() {
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
			{render.ElasticsearchConfigMapName, render.OperatorNamespace(), "", "", ""},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"pull-secret", "tigera-kibana", "", "", ""},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		component, err := render.Elasticsearch(logStorage, esConfig, nil, nil, false,
			[]*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret"}}}, operator.ProviderNone,
			&operator.Installation{Spec: operator.InstallationSpec{}},
		)
		Expect(err).NotTo(HaveOccurred())
		resources := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render an elasticsearchComponent with openShift", func() {
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
			{render.ElasticsearchConfigMapName, render.OperatorNamespace(), "", "", ""},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}

		component, err := render.Elasticsearch(logStorage, esConfig, nil, nil, false, nil, operator.ProviderOpenShift,
			&operator.Installation{Spec: operator.InstallationSpec{}},
		)
		Expect(err).NotTo(HaveOccurred())
		resources := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render an elasticsearchComponent with a webhook secret", func() {
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
			{render.ElasticsearchConfigMapName, render.OperatorNamespace(), "", "", ""},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{"tigera-secure-kibana-cert", "tigera-operator", "", "v1", "Secret"},
			{"tigera-secure-kibana-cert", "tigera-kibana", "", "v1", "Secret"},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}
		component, err := render.Elasticsearch(logStorage, esConfig, nil, nil, true, nil, operator.ProviderOpenShift,
			&operator.Installation{Spec: operator.InstallationSpec{}},
		)
		Expect(err).NotTo(HaveOccurred())
		resources := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should not render Elasticsearch or Kibana cert secrets in the operator namespace when they are provided", func() {
		component, err := render.Elasticsearch(logStorage, esConfig,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}}, false, nil, operator.ProviderOpenShift,
			&operator.Installation{Spec: operator.InstallationSpec{}},
		)
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
			{render.ElasticsearchConfigMapName, render.OperatorNamespace(), "", "", ""},
			{"tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1alpha1", "Elasticsearch"},
			{"tigera-kibana", "", "", "v1", "Namespace"},
			{render.TigeraKibanaCertSecret, "tigera-kibana", "", "", ""},
			{"tigera-secure", "tigera-kibana", "", "", ""},
		}
		Expect(err).NotTo(HaveOccurred())
		resources := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})
})
