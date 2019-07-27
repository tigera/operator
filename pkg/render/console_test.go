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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Tigera Secure Console rendering tests", func() {
	var instance *operator.Installation
	var client client.Client
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
		client = fake.NewFakeClient()
	})

	It("should render all resources for a default configuration", func() {
		component := render.Console(instance, client)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(9))

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "cnx-manager", ns: "calico-monitoring", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "cnx-manager-role", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "cnx-manager-binding", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "manager-tls", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "cnx-manager-tls", ns: "calico-monitoring", group: "", version: "v1", kind: "Secret"},
			{name: "cnx-manager", ns: "calico-monitoring", group: "", version: "v1", kind: "Deployment"},
			{name: "cnx-manager", ns: "calico-monitoring", group: "", version: "v1", kind: "Service"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})

	Context("when manager-tls in operator namespace is invalid", func() {
		BeforeEach(func() {
			badSecret := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "manager-tls",
					Namespace: "tigera-operator",
				},
				Data: map[string][]byte{},
			}
			client = fake.NewFakeClient(badSecret)
		})
		It("should not render any resources", func() {
			component := render.Console(instance, client)
			resources := component.Objects()
			Expect(len(resources)).To(Equal(0))
		})
	})
})
