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

var _ = Describe("Intrusion Detection rendering tests", func() {
	var instance *operator.Installation
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				Variant: operator.TigeraSecureEnterprise,
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Version:   "test",
				Registry:  "testregistry.com/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
			},
		}
	})

	It("should render all resources for a default configuration", func() {
		component := render.IntrusionDetection(instance)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(7))

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "intrusion-detection-controller", ns: "calico-monitoring", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection-controller", ns: "calico-monitoring", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "intrusion-detection-controller", ns: "calico-monitoring", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "intrusion-detection-controller", ns: "calico-monitoring", group: "", version: "v1", kind: "Deployment"},
			{name: "intrusion-detection-es-job-installer", ns: "calico-monitoring", group: "batch", version: "v1", kind: "Job"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})
})
