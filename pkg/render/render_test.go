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

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Rendering tests", func() {
	var instance *operatorv1alpha1.Core
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1alpha1.Core{
			Spec: operatorv1alpha1.CoreSpec{
				IPPools: []operatorv1alpha1.IPPool{
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
		resources := render.Render(instance)
		Expect(len(resources)).To(Equal(10))
	})

	It("should render all resources when kube-proxy is enabled", func() {
		// In this scenario, we expect the basic resources from the default
		// configuration plus resources for the kube-proxy, which includes
		// an additional 4 resources:
		// - kube-proxy ServiceAccount
		// - kube-proxy ClusterRoleBinding
		// - kube-proxy ConfigMap
		// - kube-proxy DaemonSet
		instance.Spec.Components.KubeProxy.Required = true
		resources := render.Render(instance)
		Expect(len(resources)).To(Equal(14))
	})

	It("should render all resources when API server is enabled", func() {
		instance.Spec.Components.APIServer = &operatorv1alpha1.APIServerSpec{
			TLS: operatorv1alpha1.TLSConfig{
				Certificate: "cert",
				Key: "key",
			},
			RunAsPrivileged: true,
		}
		resources := render.Render(instance)
		Expect(len(resources)).To(Equal(20))
	})
})
