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
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/render/tiers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Tiers rendering tests", func() {
	var cfg *tiers.Config

	clusterDNSPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns.json")
	clusterDNSPolicyForOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns_ocp.json")
	guardianPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/guardian.json")
	guardianPolicyForOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/guardian_ocp.json")
	expectedAlertmanagerPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager.json")
	expectedAlertmanagerMeshPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager-mesh.json")
	expectedPrometheusPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus.json")
	expectedPrometheusApiPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-api.json")
	expectedPrometheusOperatorPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-operator.json")
	expectedAlertmanagerPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager_ocp.json")
	expectedAlertmanagerMeshPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager-mesh_ocp.json")
	expectedPrometheusPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus_ocp.json")
	expectedPrometheusApiPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-api_ocp.json")
	expectedPrometheusOperatorPolicyOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-operator_ocp.json")

	BeforeEach(func() {
		// Establish default config for test cases to override.
		cfg = &tiers.Config{
			Openshift:                   false,
			ManagementClusterConnection: nil,
		}
	})

	Context("allow-tigera rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "allow-tigera.cluster-dns", Namespace: "kube-system"},
			{Name: "allow-tigera.cluster-dns", Namespace: "openshift-dns"},
			{Name: "allow-tigera.guardian-access", Namespace: "tigera-guardian"},
		}

		getExpectedPolicy := func(name types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if name.Name == "allow-tigera.calico-node-alertmanager" {
				return testutils.SelectPolicyByProvider(scenario, expectedAlertmanagerPolicy, expectedAlertmanagerPolicyForOpenshift)
			} else if name.Name == "allow-tigera.calico-node-alertmanager-mesh" {
				return testutils.SelectPolicyByProvider(scenario, expectedAlertmanagerMeshPolicy, expectedAlertmanagerMeshPolicyForOpenshift)
			} else if name.Name == "allow-tigera.prometheus" {
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusPolicy, expectedPrometheusPolicyForOpenshift)
			} else if name.Name == "allow-tigera.tigera-prometheus-api" {
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusApiPolicy, expectedPrometheusApiPolicyForOpenshift)
			} else if name.Name == "allow-tigera.prometheus-operator" {
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusOperatorPolicy, expectedPrometheusOperatorPolicyOpenshift)
			} else if name.Name == "allow-tigera.guardian-access" && scenario.ManagedCluster {
				return testutils.SelectPolicyByProvider(scenario, guardianPolicy, guardianPolicyForOCP)
			} else if name.Name == "allow-tigera.cluster-dns" &&
				((scenario.Openshift && name.Namespace == "openshift-dns") || (!scenario.Openshift && name.Namespace == "kube-system")) {
				return testutils.SelectPolicyByProvider(scenario, clusterDNSPolicy, clusterDNSPolicyForOCP)
			}

			return nil
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.Openshift = scenario.Openshift
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{
						ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
						Spec:       operatorv1.ManagementClusterConnectionSpec{ManagementClusterAddr: "127.0.0.1:1234"},
					}
				}
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

		// The test matrix above validates against an IP-based management cluster address.
		// Validate policy adaptation for domain-based management cluster address here.
		It("should adapt Guardian policy if ManagementClusterAddr is domain-based", func() {
			component := tiers.Tiers(&tiers.Config{
				Openshift: false,
				ManagementClusterConnection: &operatorv1.ManagementClusterConnection{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec:       operatorv1.ManagementClusterConnectionSpec{ManagementClusterAddr: "mydomain.io:8080"},
				},
			})
			resourcesToCreate, _ := component.Objects()
			policyName := types.NamespacedName{Name: "allow-tigera.guardian-access", Namespace: "tigera-guardian"}
			policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resourcesToCreate)
			managementClusterEgressRule := policy.Spec.Egress[4]
			Expect(managementClusterEgressRule.Destination.Domains).To(Equal([]string{"mydomain.io"}))
			Expect(managementClusterEgressRule.Destination.Ports).To(Equal(networkpolicy.Ports(8080)))
		})

	})
})
