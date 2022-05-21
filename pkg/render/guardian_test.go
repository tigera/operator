// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/testutils"
	"k8s.io/apimachinery/pkg/types"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Rendering tests", func() {
	var g render.Component
	var resources []client.Object

	var renderGuardian = func(i operatorv1.InstallationSpec, addr string, openshift bool) {
		secret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.GuardianSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"cert": []byte("foo"),
				"key":  []byte("bar"),
			},
		}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		bundle := certificateManager.CreateTrustedBundle()

		cfg := &render.GuardianConfiguration{
			URL: addr,
			PullSecrets: []*corev1.Secret{{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pull-secret",
					Namespace: common.OperatorNamespace(),
				},
			}},
			Installation:      &i,
			TunnelSecret:      secret,
			TrustedCertBundle: bundle,
			Openshift:         openshift,
		}
		g = render.Guardian(cfg)
		Expect(g.ResolveImages(nil)).To(BeNil())
		resources, _ = g.Objects()
	}

	BeforeEach(func() {
		renderGuardian(operatorv1.InstallationSpec{Registry: "my-reg/"}, "127.0.0.1:1234", false)
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
			{name: render.GuardianEgressPolicyName, ns: render.GuardianNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: networkpolicy.TigeraComponentDefaultDenyPolicyName, ns: render.GuardianNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "pull-secret", ns: render.GuardianNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.GuardianServiceAccountName, ns: render.GuardianNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.GuardianClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.GuardianClusterRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.GuardianDeploymentName, ns: render.GuardianNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.GuardianServiceName, ns: render.GuardianNamespace, group: "", version: "", kind: ""},
			{name: render.GuardianSecretName, ns: render.GuardianNamespace, group: "", version: "v1", kind: "Secret"},
			{name: certificatemanagement.TrustedCertConfigMapName, ns: render.GuardianNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: render.ManagerNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.ManagerServiceAccount, ns: render.ManagerNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ManagerClusterRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ManagerClusterRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ManagerClusterSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerUserSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerClusterSettingsLayerTigera, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
			{name: render.ManagerClusterSettingsViewDefault, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))
		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment.Spec.Template.Spec.Containers[0].Image).Should(Equal("my-reg/tigera/guardian:" + components.ComponentGuardian.Version))
	})

	It("should render controlPlaneTolerations", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		renderGuardian(operatorv1.InstallationSpec{ControlPlaneTolerations: []corev1.Toleration{t}}, "127.0.0.1:1234", false)
		deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment.Spec.Template.Spec.Tolerations).Should(ContainElements(t, rmeta.TolerateCriticalAddonsOnly, rmeta.TolerateMaster))
	})

	Context("allow-tigera rendering", func() {
		// Dynamic policy: egress rule changes depending on ManagementClusterAddr.
		policyName := types.NamespacedName{Name: "allow-tigera.guardian-egress", Namespace: "tigera-guardian"}
		ipBasedExpectedEgress := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Nets:  []string{"127.0.0.1/32"},
					Ports: []numorstring.Port{{MinPort: 1234, MaxPort: 1234}},
				},
			},
		}
		domainBasedExpectedEgress := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Domains: []string{"managementclusterdomain.io"},
					Ports:   []numorstring.Port{{MinPort: 9000, MaxPort: 9000}},
				},
			},
		}
		getExpectedPolicy := func(scenario testutils.AllowTigeraScenario, expectedEgress []v3.Rule) *v3.NetworkPolicy {
			if !scenario.ManagedCluster {
				return nil
			}

			return &v3.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-tigera.guardian-egress",
					Namespace: "tigera-guardian",
				},
				Spec: v3.NetworkPolicySpec{
					Order:    &networkpolicy.HighPrecedenceOrder,
					Tier:     "allow-tigera",
					Selector: "k8s-app == 'tigera-guardian'",
					Types:    []v3.PolicyType{v3.PolicyTypeEgress},
					Egress:   expectedEgress,
				},
			}
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario, managementClusterAddr string, expectedEgress []v3.Rule) {
				renderGuardian(operatorv1.InstallationSpec{Registry: "my-reg/"}, managementClusterAddr, scenario.Openshift)

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario, expectedEgress)

				Expect(policy.ObjectMeta).To(Equal(expectedPolicy.ObjectMeta))
				Expect(policy.TypeMeta).To(Equal(expectedPolicy.TypeMeta))
				Expect(policy.Spec.Order).To(Equal(expectedPolicy.Spec.Order))
				Expect(policy.Spec.Tier).To(Equal(expectedPolicy.Spec.Tier))
				Expect(policy.Spec.Selector).To(Equal(expectedPolicy.Spec.Selector))
				Expect(policy.Spec.Types).To(Equal(expectedPolicy.Spec.Types))
				Expect(policy.Spec.Egress).To(Equal(expectedEgress))
			},
			// Guardian only renders in the presence of an ManagementClusterConnection CR, therefore does not have a config option for unmanaged clusters.
			Entry("for ip mgmt address, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}, "127.0.0.1:1234", ipBasedExpectedEgress),
			Entry("for ip mgmt address, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}, "127.0.0.1:1234", ipBasedExpectedEgress),
			Entry("for domain mgmt address, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}, "managementclusterdomain.io:9000", domainBasedExpectedEgress),
			Entry("for domain mgmt address, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}, "managementclusterdomain.io:9000", domainBasedExpectedEgress),
		)
	})
})
