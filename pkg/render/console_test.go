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

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Tigera Secure Console rendering tests", func() {
	var instance *operator.Console
	var monitoring *operator.MonitoringConfiguration
	var registry string
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Console{
			Spec: operator.ConsoleSpec{
				Auth: &operator.Auth{
					Type: operator.AuthTypeBasic,
				},
			},
		}
		monitoring = &operator.MonitoringConfiguration{
			Spec: operator.MonitoringConfigurationSpec{
				ClusterName: "clusterTestName",
				Elasticsearch: &operator.ElasticConfig{
					Endpoint: "https://elastic.search:1234",
				},
				Kibana: &operator.KibanaConfig{
					Endpoint: "https://kibana.ui:1234",
				},
			},
		}
	})

	It("should render all resources for a default configuration", func() {
		component, err := render.Console(instance, monitoring, nil, nil, notOpenshift, registry)
		Expect(err).To(BeNil(), "Expected Console to create successfully %s", err)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(10))

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-console", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "cnx-manager", ns: "tigera-console", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "cnx-manager-role", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "cnx-manager-binding", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "manager-tls", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "manager-tls", ns: "tigera-console", group: "", version: "v1", kind: "Secret"},
			{name: "cnx-manager", ns: "tigera-console", group: "", version: "v1", kind: "Deployment"},
			{name: "cnx-manager", ns: "tigera-console", group: "", version: "v1", kind: "Service"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})
})
