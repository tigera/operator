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
	v1 "k8s.io/api/core/v1"
)

var _ = Describe("kube-proxy rendering tests", func() {
	var instance *operatorv1alpha1.Core
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1alpha1.Core{
			Spec: operatorv1alpha1.CoreSpec{
				IPPools: []operatorv1alpha1.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Version:        "test",
				Registry:       "test-reg/",
				CNINetDir:      "/test/cni/net/dir",
				CNIBinDir:      "/test/cni/bin/dir",
				APIServer:      "https://apiserver:443",
				KubeProxyImage: "k8s.gcr.io/kube-proxy:v1.12.7",
			},
		}

	})

	It("should render all resources for a default configuration", func() {
		resources := render.KubeProxy(instance)
		Expect(len(resources)).To(Equal(4))

		// Should render the correct resources.
		ExpectResource(resources[0], "kube-proxy", "kube-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "kube-proxy", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[2], "kube-proxy", "kube-system", "", "v1", "ConfigMap")
		ExpectResource(resources[3], "kube-proxy", "kube-system", "apps", "v1", "DaemonSet")

		// The DaemonSet should have the correct configuration.
		ds := resources[3].(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("k8s.gcr.io/kube-proxy:v1.12.7"))

		// The ConfigMap should have the right info.
		cm := resources[2].(*v1.ConfigMap)
		Expect(cm.Data["kubeconfig.conf"]).To(ContainSubstring("server: https://apiserver:443"))
		Expect(cm.Data["config.conf"]).To(ContainSubstring("clusterCIDR: 192.168.1.0/16"))
	})
})
