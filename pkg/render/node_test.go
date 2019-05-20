// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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
	apps "k8s.io/api/apps/v1"
)

var _ = Describe("Node rendering tests", func() {
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
		resources := render.Node(instance)
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-node", "kube-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "cni-config", "kube-system", "", "v1", "ConfigMap")
		ExpectResource(resources[4], "calico-node", "kube-system", "apps", "v1", "DaemonSet")

		// The DaemonSet should have the correct configuration.
		ds := resources[4].(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/calico/node:test"))
		ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")
		ExpectEnv(ds.Spec.Template.Spec.InitContainers[0].Env, "CNI_NET_DIR", "/test/cni/net/dir")
	})
})
