// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package tiers_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/render/tiers"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Tiers rendering tests", func() {
	var cfg *tiers.Config

	apiServerPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/apiserver.json")
	apiServerPolicyForOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/apiserver_ocp.json")
	clusterDNSPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns.json")
	clusterDNSPolicyForOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns_ocp.json")
	kcPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers.json")
	kcPolicyForUnmanagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_ocp.json")
	kcPolicyForManaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_managed.json")
	kcPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_managed_ocp.json")
	pcPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/packetcapture.json")
	pcPolicyForUnmanagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/packetcapture_ocp.json")
	pcPolicyForManaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/packetcapture_managed.json")
	pcPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/packetcapture_managed_ocp.json")

	BeforeEach(func() {
		// Establish default config for test cases to override.
		cfg = &tiers.Config{
			Openshift:      false,
			ManagedCluster: false,
		}
	})

	Context("allow-tigera rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "allow-tigera.cnx-apiserver-access", Namespace: "tigera-system"},
			{Name: "allow-tigera.cluster-dns", Namespace: "kube-system"},
			{Name: "allow-tigera.cluster-dns", Namespace: "openshift-dns"},
			{Name: "allow-tigera.kube-controller-access", Namespace: "calico-system"},
			{Name: "allow-tigera.tigera-packetcapture", Namespace: "tigera-packetcapture"},
		}

		getExpectedPolicy := func(name types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if name.Name == "allow-tigera.cnx-apiserver-access" {
				return testutils.SelectPolicyByProvider(scenario, apiServerPolicy, apiServerPolicyForOCP)
			} else if name.Name == "allow-tigera.kube-controller-access" {
				return testutils.SelectPolicyByClusterTypeAndProvider(
					scenario,
					kcPolicyForUnmanaged,
					kcPolicyForUnmanagedOCP,
					kcPolicyForManaged,
					kcPolicyForManagedOCP,
				)
			} else if name.Name == "allow-tigera.tigera-packetcapture" {
				return testutils.SelectPolicyByClusterTypeAndProvider(
					scenario,
					pcPolicyForUnmanaged,
					pcPolicyForUnmanagedOCP,
					pcPolicyForManaged,
					pcPolicyForManagedOCP,
				)
			} else if name.Name == "allow-tigera.cluster-dns" &&
				((scenario.Openshift && name.Namespace == "openshift-dns") || (!scenario.Openshift && name.Namespace == "kube-system")) {
				return testutils.SelectPolicyByProvider(scenario, clusterDNSPolicy, clusterDNSPolicyForOCP)
			}

			return nil
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.Openshift = scenario.Openshift
				cfg.ManagedCluster = scenario.ManagedCluster
				component := tiers.Tiers(cfg)
				resourcesToCreate, resourcesToDelete := component.Objects()

				// Validate tier render
				allowTigera := rtest.GetResource(resourcesToCreate, "allow-tigera", "", "projectcalico.org", "v3", "Tier").(*v3.Tier)
				Expect(*allowTigera.Spec.Order).To(Equal(100.0))

				// Validate created policy render
				for _, policyName := range policyNames {
					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}

				// Validate deleted policy render
				if !scenario.Openshift {
					Expect(resourcesToDelete).To(HaveLen(2))
					Expect(resourcesToDelete[0].GetName()).To(Equal("allow-tigera.kube-dns"))
					Expect(resourcesToDelete[0].GetNamespace()).To(Equal("kube-system"))
					Expect(resourcesToDelete[1].GetName()).To(Equal("allow-tigera.kube-dns-egress"))
					Expect(resourcesToDelete[1].GetNamespace()).To(Equal("kube-system"))
				} else {
					Expect(resourcesToDelete).To(BeEmpty())
				}
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
		)
	})
})
