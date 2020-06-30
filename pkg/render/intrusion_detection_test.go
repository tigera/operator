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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Intrusion Detection rendering tests", func() {
	It("should render all resources for a default configuration", func() {
		esConfigMap := render.NewElasticsearchClusterConfig("clusterTestName", 1, 1, 1)

		component := render.IntrusionDetection(
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operator.Installation{Spec: operator.InstallationSpec{Registry: "testregistry.com/"}},
			esConfigMap, nil, notOpenshift,
		)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-intrusion-detection", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.TigeraKibanaCertSecret, ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Deployment"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "policy.pod", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkpolicy", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkset", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.serviceaccount", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.cloudapi", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.ssh", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.access", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.originate", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "intrusion-detection-controller-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			if expectedRes.kind == "GlobalAlertTemplate" {
				ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}
	})
})
