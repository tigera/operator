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

var _ = Describe("Rendering tests", func() {
	var instance *operator.Installation
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Version:   "test",
				Registry:  "test-reg/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
			},
		}

	})

	It("should render all resources for a default configuration", func() {
		// For this scenario, we expect the basic resources
		// created by the controller without any optional ones. These include:
		// - 5 node resources (ServiceAccount, ClusterRole, Binding, ConfigMap, DaemonSet)
		// - 4 kube-controllers resources (ServiceAccount, ClusterRole, Binding, Deployment)
		// - 1 namespace
		// - 1 PriorityClass
		// - 14 custom resource definitions
		components := render.Render(instance)
		Expect(componentCount(components)).To(Equal(25))
	})

	It("should render all resources when kube-proxy is enabled", func() {
		// In this scenario, we expect the basic resources from the default
		// configuration plus resources for the kube-proxy, which includes
		// an additional 4 resources:
		// - kube-proxy ServiceAccount
		// - kube-proxy ClusterRoleBinding
		// - kube-proxy ConfigMap
		// - kube-proxy DaemonSet
		// - 1 PriorityClass
		// - 14 custom resource definitions
		instance.Spec.Components.KubeProxy.Required = true
		components := render.Render(instance)
		Expect(componentCount(components)).To(Equal(29))
	})

	It("should render all resources when variant is Tigera Secure", func() {
		// For this scenario, we expect the basic resources plus the following 10 resources for Tigera Secure:
		// - 1 additional namespace
		// - 1 APIService
		// - 2 ClusterRole
		// - 3 ClusterRoleBindings
		// - 1 RoleBinding
		// - 1 ConfigMap
		// - 1 Deployment
		// - 1 Service
		// - 1 ServiceAccount
		// - 1 PriorityClass
		// - 14 custom resource definitions (calico)
		// - 6 custom resource definitions (tsee)
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		components := render.Render(instance)
		Expect(componentCount(components)).To(Equal(43))
	})
})

func componentCount(components []render.Component) int {
	count := 0
	for _, c := range components {
		count += len(c.GetObjects())
	}
	return count
}

