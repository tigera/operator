// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

	clusterDNSPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns.json")
	clusterDNSPolicyForOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns_ocp.json")
	nodeLocalDNSPolicy := testutils.GetExpectedGlobalPolicyFromFile("../testutils/expected_policies/node_local_dns.json")

	BeforeEach(func() {
		// Establish default config for test cases to override.
		cfg = &tiers.Config{
			Openshift:    false,
			NodeLocalDNS: false,
			KubeDNSCIDR:  "10.96.0.10/32",
		}
	})

	Context("allow-tigera rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "allow-tigera.cluster-dns", Namespace: "kube-system"},
			{Name: "allow-tigera.cluster-dns", Namespace: "openshift-dns"},
		}

		getExpectedPolicy := func(name types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if name.Name == "allow-tigera.cluster-dns" &&
				((scenario.Openshift && name.Namespace == "openshift-dns") || (!scenario.Openshift && name.Namespace == "kube-system")) {
				return testutils.SelectPolicyByProvider(scenario, clusterDNSPolicy, clusterDNSPolicyForOCP)
			}

			return nil
		}

		DescribeTable("should render allow-tigera network policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.Openshift = scenario.Openshift
				cfg.NodeLocalDNS = scenario.NodeLocalDNS
				component := tiers.Tiers(cfg)
				resourcesToCreate, _ := component.Objects()

				// Validate tier render
				allowTigera := rtest.GetResource(resourcesToCreate, "allow-tigera", "", "projectcalico.org", "v3", "Tier").(*v3.Tier)
				Expect(*allowTigera.Spec.Order).To(Equal(100.0))

				// Validate created policy render
				for _, policyName := range policyNames {
					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},

			// NodeLocalDNS is not supported on Openshift so no need to test Openshift:true with NodeLocalDNS: true
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false, NodeLocalDNS: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true, NodeLocalDNS: false}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false, NodeLocalDNS: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true, NodeLocalDNS: false}),
		)
	})

	Context("allow-tigera global policy rendering", func() {
		globalPolicyNames := []string{
			"allow-tigera.node-local-dns",
		}

		getExpectedGlobalPolicy := func(name string, scenario testutils.AllowTigeraScenario) *v3.GlobalNetworkPolicy {
			if name == "allow-tigera.node-local-dns" &&
				!scenario.Openshift && scenario.NodeLocalDNS {
				return nodeLocalDNSPolicy
			}

			return nil
		}

		DescribeTable("should render allow-tigera global network policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.Openshift = scenario.Openshift
				cfg.NodeLocalDNS = scenario.NodeLocalDNS
				component := tiers.Tiers(cfg)
				resourcesToCreate, _ := component.Objects()

				// Validate tier render
				allowTigera := rtest.GetGlobalResource(resourcesToCreate, "allow-tigera", "projectcalico.org", "v3", "Tier").(*v3.Tier)
				Expect(*allowTigera.Spec.Order).To(Equal(100.0))

				// Validate created policy render
				for _, policyName := range globalPolicyNames {
					policy := testutils.GetAllowTigeraGlobalPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedGlobalPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},

			// NodeLocalDNS is not supported on Openshift so no need to test Openshift:true with NodeLocalDNS: true
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false, NodeLocalDNS: false}),
			Entry("for management/standalone, kube-dns, node-local-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false, NodeLocalDNS: true}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true, NodeLocalDNS: false}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false, NodeLocalDNS: false}),
			Entry("for managed, kube-dns, node-local-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false, NodeLocalDNS: true}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true, NodeLocalDNS: false}),
		)
	})
})
