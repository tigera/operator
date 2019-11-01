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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{{CIDR: "192.168.1.0/16"}},
				},
				Registry: "test-reg/",
			},
		}

	})

	It("should render all resources for a custom configuration", func() {
		component := render.KubeControllers(instance)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(4))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-kube-controllers", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")

		// The Deployment should have the correct configuration.
		ds := resources[3].(*apps.Deployment)

		// Image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("test-reg/%s", render.KubeControllersImageNameCalico)))

		// Verify env
		expectedEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "ENABLED_CONTROLLERS", Value: "node"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// Verify tolerations.
		expectedTolerations := []v1.Toleration{
			{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
			{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectNoSchedule},
		}
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
		instance.Spec.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(instance)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(4))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-kube-controllers", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")

		// The Deployment should have the correct configuration.
		ds := resources[3].(*apps.Deployment)

		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/kube-controllers:release-v2.6"))
	})
})
