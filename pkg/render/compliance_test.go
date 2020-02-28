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
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/elasticsearch"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("compliance rendering tests", func() {
	var instance *operatorv1.Installation
	BeforeEach(func() {
		instance = &operatorv1.Installation{
			Spec: operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			},
		}
		esusers.AddUser(elasticsearch.User{Username: render.ElasticsearchUserComplianceBenchmarker})
		esusers.AddUser(elasticsearch.User{Username: render.ElasticsearchUserComplianceController})
		esusers.AddUser(elasticsearch.User{Username: render.ElasticsearchUserComplianceReporter})
		esusers.AddUser(elasticsearch.User{Username: render.ElasticsearchUserComplianceSnapshotter})
		esusers.AddUser(elasticsearch.User{Username: render.ElasticsearchUserComplianceServer})
	})

	It("should render all resources for a default configuration", func() {
		replicas := int32(0)
		ls := &operatorv1.LogStorage{
			Spec: operatorv1.LogStorageSpec{
				Indices: &operatorv1.Indices{Replicas: &replicas},
			},
			Status: operatorv1.LogStorageStatus{
				ElasticsearchHash: "randomhash",
			},
		}

		component := render.Compliance(ls, nil, instance, "clusterTestName", nil, notOpenshift)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(28))
		ns := "tigera-compliance"
		rbac := "rbac.authorization.k8s.io"
		idx := 0

		// Should render the correct resources.
		ExpectResource(resources[idx], ns, "", "", "v1", "Namespace")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", ns, rbac, "v1", "Role")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", "", rbac, "v1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", ns, rbac, "v1", "RoleBinding")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "compliance-controller", ns, "apps", "v1", "Deployment")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-reporter", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-reporter", "", rbac, "v1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "tigera.io.report", ns, "", "v1", "PodTemplate")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-server", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-server", "", rbac, "v1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "compliance", ns, "", "v1", "Service")
		idx++
		ExpectResource(resources[idx], "compliance-server", ns, "apps", "v1", "Deployment")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "compliance-snapshotter", ns, "apps", "v1", "Deployment")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole")
		idx++
		ExpectResource(resources[idx], "tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding")
		idx++
		ExpectResource(resources[idx], "compliance-benchmarker", ns, "apps", "v1", "DaemonSet")
		idx++
		ExpectGlobalReportType(resources[idx], "inventory")
		idx++
		ExpectGlobalReportType(resources[idx], "network-access")
		idx++
		ExpectGlobalReportType(resources[idx], "policy-audit")
		idx++
		ExpectGlobalReportType(resources[idx], "cis-benchmark")
	})
})
