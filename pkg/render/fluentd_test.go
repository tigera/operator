// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Tigera Secure Fluentd rendering tests", func() {
	var instance *operatorv1.LogCollector
	var monitoring *operatorv1.MonitoringConfiguration
	var registry string
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1.LogCollector{}
		monitoring = &operatorv1.MonitoringConfiguration{
			Spec: operatorv1.MonitoringConfigurationSpec{
				ClusterName: "clusterTestName",
				Elasticsearch: &operatorv1.ElasticConfig{
					Endpoint: "https://elastic.search:1234",
				},
				Kibana: &operatorv1.KibanaConfig{
					Endpoint: "https://kibana.ui:1234",
				},
			},
		}
	})

	It("should render all resources for a default configuration", func() {
		component := render.Fluentd(instance, nil, "", nil, operatorv1.ProviderNone, registry)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(2))

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-log-collector", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "fluentd", ns: "tigera-log-collector", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})
})
