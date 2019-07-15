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

var _ = Describe("compliance rendering tests", func() {
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
				Components: operator.ComponentsSpec{
					APIServer: operator.APIServerSpec{},
				},
			},
		}
	})

	It("should render all resources for a default configuration", func() {
		component := render.Compliance(instance)
		resources := component.GetObjects()
		Expect(len(resources)).To(Equal(27))
		ns := "calico-monitoring"
		rbac := "rbac.authorization.k8s.io"
		idx := 0

		// Should render the correct resources.
		ExpectResource(resources[idx], "tigera-compliance-controller", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", ns, rbac, "v1beta1", "Role")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", "", rbac, "v1beta1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", ns, rbac, "v1beta1", "RoleBinding")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", "", rbac, "v1beta1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "compliance-controller", ns, "apps", "v1", "Deployment")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-reporter", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-reporter", "", rbac, "v1beta1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-reporter", "", rbac, "v1beta1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "tigera.io.report", ns, "", "v1", "PodTemplate")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-server", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-server", "", rbac, "v1beta1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-server", "", rbac, "v1beta1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "compliance", ns, "", "v1", "Service")
		idx++
		ExpectResource(resources[idx], "compliance-server", ns, "apps", "v1", "Deployment")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-snapshotter", "", rbac, "v1beta1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-snapshotter", "", rbac, "v1beta1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "compliance-snapshotter", "", apps, "v1", "Deployment")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", ns, rbac, "v1beta1", "Role")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", "", rbac, "v1beta1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", ns, rbac, "v1beta1", "RoleBinding")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", ns, "", "appsv1", "DaemonSet")
		idx++
		ExpectResource(resources[idx], "inventory", "", "projectcalico.org/v3", "appsv1", "GlobalReportType")
		idx++
		ExpectResource(resources[idx], "network-access", "", "projectcalico.org/v3", "appsv1", "GlobalReportType")
		idx++
		ExpectResource(resources[idx], "policy-audit", "", "projectcalico.org/v3", "appsv1", "GlobalReportType")
		idx++
		ExpectResource(resources[idx], "cis-benchmark", "", "projectcalico.org/v3", "appsv1", "GlobalReportType")
	})
})
