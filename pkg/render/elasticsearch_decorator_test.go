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

package render

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	"github.com/tigera/operator/pkg/dns"

	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Elasticsearch decorator tests", func() {
	var container corev1.Container

	BeforeEach(func() {
		container = corev1.Container{
			Name:  "test",
			Image: "some image",
			Env: []corev1.EnvVar{
				{Name: "TEST_ENV1", Value: "8080"},
				{Name: "TEST_ENV2", Value: "INFO"},
			},
			VolumeMounts: []corev1.VolumeMount{{
				Name:      "temp",
				MountPath: "/tmp/",
				ReadOnly:  true,
			}},
		}
	})
	Context("ElasticsearchContainerDecorate", func() {
		DescribeTable("should decorate a container with the ES host and port", func(clusterDomain, expectedESHost string, os OSType) {
			c := ElasticsearchContainerDecorate(container, "test-cluster", "secret", clusterDomain, os)

			expectedEnvs := []corev1.EnvVar{
				{Name: "ELASTIC_HOST", Value: expectedESHost},
				{Name: "ELASTIC_PORT", Value: "9200"},
			}
			for _, expected := range expectedEnvs {
				Expect(c.Env).To(ContainElement(expected))
			}
		},
			Entry("linux", dns.DefaultClusterDomain, "tigera-secure-es-http.tigera-elasticsearch.svc", OSTypeLinux),
			Entry("linux ignores cluster domain", "does.not.matter", "tigera-secure-es-http.tigera-elasticsearch.svc", OSTypeLinux),
			Entry("windows", "acme.internal", "tigera-secure-es-http.tigera-elasticsearch.svc.acme.internal", OSTypeWindows),
		)
	})
})
