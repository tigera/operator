// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Rendering tests", func() {
	var g render.Component
	var resources []client.Object

	var renderGuardian = func(i operator.InstallationSpec) {
		addr := "127.0.0.1:1234"
		secret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.GuardianSecretName,
				Namespace: rmeta.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"cert": []byte("foo"),
				"key":  []byte("bar"),
			},
		}
		g = render.Guardian(
			addr,
			[]*corev1.Secret{{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pull-secret",
					Namespace: rmeta.OperatorNamespace(),
				},
			}},
			false,
			&i,
			secret,
		)
		Expect(g.ResolveImages(nil)).To(BeNil())
		resources, _ = g.Objects()
		return
	}

	BeforeEach(func() {
		renderGuardian(operator.InstallationSpec{Registry: "my-reg/"})
	})

	It("should render all resources for a managed cluster", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: render.GuardianNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "pull-secret", ns: render.GuardianNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.GuardianServiceAccountName, ns: render.GuardianNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.GuardianClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.GuardianClusterRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.GuardianDeploymentName, ns: render.GuardianNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.GuardianServiceName, ns: render.GuardianNamespace, group: "", version: "", kind: ""},
			{name: render.GuardianSecretName, ns: render.GuardianNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.ManagerNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.ManagerServiceAccount, ns: render.ManagerNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ManagerClusterRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ManagerClusterRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))
		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment.Spec.Template.Spec.Containers[0].Image).Should(Equal("my-reg/tigera/guardian:" + components.ComponentGuardian.Version))
		Expect(deployment.Spec.Template.Spec.Containers[1].Image).Should(Equal("my-reg/tigera/packetcapture-api:" + components.ComponentPacketCapture.Version))

		clusterRole := rtest.GetResource(resources, render.GuardianClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"packetcaptures"},
				Verbs:     []string{"get"},
			},
		}))
	})

	It("should render controlPlaneTolerations", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		renderGuardian(operator.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
		})
		deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment.Spec.Template.Spec.Tolerations).Should(ContainElements(t, rmeta.TolerateCriticalAddonsOnly, rmeta.TolerateMaster))
	})
})
