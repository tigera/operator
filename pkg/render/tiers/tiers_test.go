// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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
	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/render/tiers"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Tiers rendering tests", func() {
	var cfg *tiers.Config

	clusterDNSPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns.json")
	clusterDNSPolicyForOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns_ocp.json")
	nodeLocalDNSPolicyIPv4 := testutils.GetExpectedGlobalPolicyFromFile("../testutils/expected_policies/node_local_dns_ipv4.json")
	nodeLocalDNSPolicyIPv6 := testutils.GetExpectedGlobalPolicyFromFile("../testutils/expected_policies/node_local_dns_ipv6.json")
	nodeLocalDNSPolicyDual := testutils.GetExpectedGlobalPolicyFromFile("../testutils/expected_policies/node_local_dns_dual.json")

	getDNSEgressCIDRs := func(ipMode testutils.IPMode) tiers.DNSEgressCIDR {
		switch ipMode {
		case testutils.IPV4:
			return tiers.DNSEgressCIDR{
				IPV4: []string{"10.96.0.10/32"},
			}

		case testutils.IPV6:
			return tiers.DNSEgressCIDR{
				IPV6: []string{"2002:a60:a::"},
			}
		case testutils.DualStack:
			return tiers.DNSEgressCIDR{
				IPV4: []string{"10.96.0.10/32"},
				IPV6: []string{"2002:a60:a::"},
			}
		// default to IPV4 if ipMode is not set.
		default:
			return tiers.DNSEgressCIDR{
				IPV4: []string{"10.96.0.10/32"},
			}
		}
	}

	BeforeEach(func() {
		// Establish default config for test cases to override.
		cfg = &tiers.Config{
			OpenShift:      false,
			DNSEgressCIDRs: getDNSEgressCIDRs(testutils.IPV4),
			CalicoNamespaces: []string{
				common.CalicoNamespace,
				render.GuardianNamespace,
				render.ComplianceNamespace,
				render.DexNamespace,
				render.ElasticsearchNamespace,
				render.LogCollectorNamespace,
				render.IntrusionDetectionNamespace,
				kibana.Namespace,
				render.ManagerNamespace,
				eck.OperatorNamespace,
				render.PacketCaptureNamespace,
				render.PolicyRecommendationNamespace,
				common.TigeraPrometheusNamespace,
				rmeta.APIServerNamespace(v1.TigeraSecureEnterprise),
				"tigera-skraper",
			},
		}
	})

	Context("allow-tigera rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "allow-tigera.cluster-dns", Namespace: "kube-system"},
			{Name: "allow-tigera.cluster-dns", Namespace: "openshift-dns"},
		}

		getExpectedPolicy := func(name types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if name.Name == "allow-tigera.cluster-dns" &&
				((scenario.OpenShift && name.Namespace == "openshift-dns") || (!scenario.OpenShift && name.Namespace == "kube-system")) {
				return testutils.SelectPolicyByProvider(scenario, clusterDNSPolicy, clusterDNSPolicyForOCP)
			}

			return nil
		}

		DescribeTable("should render allow-tigera network policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.OpenShift = scenario.OpenShift

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

			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: true}),
		)
	})

	Context("allow-tigera node-local-dns global policy rendering", func() {
		globalPolicyNames := []string{
			"allow-tigera.node-local-dns",
		}

		getExpectedPolicy := func(ipMode testutils.IPMode) *v3.GlobalNetworkPolicy {
			switch ipMode {
			case testutils.IPV4:
				return nodeLocalDNSPolicyIPv4
			case testutils.IPV6:
				return nodeLocalDNSPolicyIPv6
			case testutils.DualStack:
				return nodeLocalDNSPolicyDual
			// default behaviour is IPV4
			default:
				return nodeLocalDNSPolicyIPv4
			}
		}

		DescribeTable("should render for single and dual stack",
			func(ipMode testutils.IPMode) {
				cfg.DNSEgressCIDRs = getDNSEgressCIDRs(ipMode)
				component := tiers.Tiers(cfg)
				resourcesToCreate, _ := component.Objects()

				// Validate tier render
				allowTigera := rtest.GetGlobalResource(resourcesToCreate, "allow-tigera", "projectcalico.org", "v3", "Tier").(*v3.Tier)
				Expect(*allowTigera.Spec.Order).To(Equal(100.0))

				// Validate created policy render
				for _, policyName := range globalPolicyNames {
					policy := testutils.GetAllowTigeraGlobalPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedPolicy(ipMode)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},

			Entry("for IPV4", testutils.IPV4),
			Entry("for IPV6", testutils.IPV6),
			Entry("for DualStack", testutils.DualStack),
			Entry("for when ipMode is not provided", nil),
		)
	})
})
