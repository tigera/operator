// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	"net"
	"net/url"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
)

var _ = Describe("Rendering tests", func() {
	var cfg *render.GuardianConfiguration
	var g render.Component
	var resources []client.Object

	createGuardianConfig := func(i operatorv1.InstallationSpec, addr string, proxyAddr string, openshift bool) *render.GuardianConfiguration {
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
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle := certificateManager.CreateTrustedBundle()

		return &render.GuardianConfiguration{
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
			OpenShift:         openshift,
		}
	}

	Context("Guardian component", func() {
		renderGuardian := func(i operatorv1.InstallationSpec) {
			cfg = createGuardianConfig(i, "127.0.0.1:1234", "", false)
			g = render.Guardian(cfg)
			Expect(g.ResolveImages(nil)).To(BeNil())
			resources, _ = g.Objects()
		}

		BeforeEach(func() {
			renderGuardian(operatorv1.InstallationSpec{Registry: "my-reg/"})
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
				{name: "tigera-ca-bundle", ns: render.GuardianNamespace, group: "", version: "v1", kind: "ConfigMap"},
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
				rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(deployment.Spec.Template.Spec.Containers[0].Image).Should(Equal("my-reg/tigera/guardian:" + components.ComponentGuardian.Version))

			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(deployment.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
			Expect(deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))

			// Check the namespace.
			ns := rtest.GetResource(resources, "tigera-guardian", "", "", "v1", "Namespace").(*corev1.Namespace)
			Expect(ns.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
			Expect(ns.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

			crb := rtest.GetResource(resources, render.ManagerClusterRoleBinding, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(crb.Subjects).To(Equal([]rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      render.ManagerServiceAccount,
				Namespace: render.ManagerNamespace,
			}}))
		})

		It("should render controlPlaneTolerations", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}
			renderGuardian(operatorv1.InstallationSpec{
				ControlPlaneTolerations: []corev1.Toleration{t},
			})
			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment.Spec.Template.Spec.Tolerations).Should(ContainElements(append(rmeta.TolerateCriticalAddonsAndControlPlane, t)))
		})
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		component := render.Guardian(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "tigera-guardian", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	Context("GuardianPolicy component", func() {
		guardianPolicy := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/guardian.json")
		guardianPolicyForOCP := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/guardian_ocp.json")

		renderGuardianPolicy := func(addr string, proxyAddr string, openshift bool) {
			cfg := createGuardianConfig(operatorv1.InstallationSpec{Registry: "my-reg/"}, addr, proxyAddr, openshift)
			g, err := render.GuardianPolicy(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ = g.Objects()
		}

		Context("allow-tigera rendering", func() {
			policyName := types.NamespacedName{Name: "allow-tigera.guardian-access", Namespace: "tigera-guardian"}

			getExpectedPolicy := func(name types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
				if name.Name == "allow-tigera.guardian-access" && scenario.ManagedCluster {
					return testutils.SelectPolicyByProvider(scenario, guardianPolicy, guardianPolicyForOCP)
				}

				return nil
			}

			DescribeTable("should render allow-tigera policy",
				func(scenario testutils.AllowTigeraScenario) {
					renderGuardianPolicy("127.0.0.1:1234", "", scenario.OpenShift)
					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: false}),
				Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: true}),
			)

			// The test matrix above validates against an IP-based management cluster address.
			// Validate policy adaptation for domain-based management cluster address here.

			DescribeTable("should adapt Guardian policy based on destination type", func(destAddr, proxyAddr string) {
				renderGuardianPolicy(destAddr, proxyAddr, false)
				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				Expect(policy.Spec.Egress).To(HaveLen(7))
				managementClusterEgressRule := policy.Spec.Egress[5]

				isProxied := proxyAddr != ""
				var expectedHost string
				var expectedPortString string
				if isProxied {
					uri, err := url.ParseRequestURI(proxyAddr)
					Expect(err).NotTo(HaveOccurred())
					expectedPortString = uri.Port()
					if expectedPortString == "" {
						expectedHost = uri.Host
						if uri.Scheme == "http" {
							expectedPortString = "80"
						} else if uri.Scheme == "https" {
							expectedPortString = "443"
						}
					} else {
						host, port, err := net.SplitHostPort(uri.Host)
						Expect(err).NotTo(HaveOccurred())
						expectedHost = host
						expectedPortString = port
					}
				} else {
					host, port, err := net.SplitHostPort(destAddr)
					Expect(err).NotTo(HaveOccurred())
					expectedHost = host
					expectedPortString = port
				}
				expectedPort, err := strconv.ParseUint(expectedPortString, 10, 16)
				Expect(err).NotTo(HaveOccurred())

				if net.ParseIP(expectedHost) != nil {
					// Host is an IP.
					Expect(managementClusterEgressRule.Destination.Nets).To(HaveLen(1))
					Expect(managementClusterEgressRule.Destination.Nets[0]).To(Equal(fmt.Sprintf("%s/32", expectedHost)))
					Expect(managementClusterEgressRule.Destination.Ports).To(Equal(networkpolicy.Ports(uint16(expectedPort))))
				} else {
					// Host is a domain name.
					Expect(managementClusterEgressRule.Destination.Domains).To(Equal([]string{expectedHost}))
					Expect(managementClusterEgressRule.Destination.Ports).To(Equal(networkpolicy.Ports(uint16(expectedPort))))
				}
			},
				Entry("domain host:port, no proxy", "mydomain.io:8080", ""),
				Entry("domain host:port, http proxy domain host", "mydomain.io:8080", "http://myproxy.io/"),
				Entry("domain host:port, https proxy domain host", "mydomain.io:8080", "https://myproxy.io/"),
				Entry("domain host:port, http proxy domain host:port", "mydomain.io:8080", "http://myproxy.io:9000/"),
				Entry("domain host:port, https proxy domain host:port", "mydomain.io:8080", "https://myproxy.io:9000/"),
				Entry("domain host:port, http proxy ip host", "mydomain.io:8080", "http://10.0.0.1/"),
				Entry("domain host:port, https proxy ip host", "mydomain.io:8080", "https://10.0.0.1/"),
				Entry("domain host:port, http proxy ip host:port", "mydomain.io:8080", "http://10.0.0.1:9000/"),
				Entry("domain host:port, https proxy ip host:port", "mydomain.io:8080", "https://10.0.0.1:9000/"),
				Entry("ip host:port, no proxy", "192.168.0.01:8080", ""),
				Entry("ip host:port, http proxy domain host", "192.168.0.01:8080", "http://myproxy.io/"),
				Entry("ip host:port, https proxy domain host", "192.168.0.01:8080", "https://myproxy.io/"),
				Entry("ip host:port, http proxy domain host:port", "192.168.0.01:8080", "http://myproxy.io:9000/"),
				Entry("ip host:port, https proxy domain host:port", "192.168.0.01:8080", "https://myproxy.io:9000/"),
				Entry("ip host:port, http proxy ip host", "192.168.0.01:8080", "http://10.0.0.1/"),
				Entry("ip host:port, https proxy ip host", "192.168.0.01:8080", "https://10.0.0.1/"),
				Entry("ip host:port, http proxy ip host:port", "192.168.0.01:8080", "http://10.0.0.1:9000/"),
				Entry("ip host:port, https proxy ip host:port", "192.168.0.01:8080", "https://10.0.0.1:9000/"),
			)
		})
	})
})

var _ = Describe("guardian", func() {
	Context("with public CA", func() {
		var cfg *render.GuardianConfiguration
		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

			certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			cfg = &render.GuardianConfiguration{
				PullSecrets:       []*corev1.Secret{},
				Installation:      &operatorv1.InstallationSpec{},
				TunnelSecret:      &corev1.Secret{},
				TrustedCertBundle: certificateManager.CreateTrustedBundle(),
			}
		})
		It("should render when disabled", func() {
			g := render.Guardian(cfg)
			resources, _ := g.Objects()
			Expect(resources).ToNot(BeNil())

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			rtest.ExpectEnv(container.Env, "GUARDIAN_VOLTRON_CA_TYPE", "")
		})

		It("should render when set to disabled", func() {
			cfg.TunnelCAType = operatorv1.CATypeTigera
			g := render.Guardian(cfg)
			resources, _ := g.Objects()
			Expect(resources).ToNot(BeNil())

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			rtest.ExpectEnv(container.Env, "GUARDIAN_VOLTRON_CA_TYPE", "Tigera")
		})

		It("should render when enabled", func() {
			cfg.TunnelCAType = operatorv1.CATypePublic

			g := render.Guardian(cfg)
			resources, _ := g.Objects()
			Expect(resources).ToNot(BeNil())

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			rtest.ExpectEnv(container.Env, "GUARDIAN_VOLTRON_CA_TYPE", "Public")
		})
		It("should render guardian with resource requests and limits when configured", func() {

			guardianResources := corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":     resource.MustParse("2"),
					"memory":  resource.MustParse("300Mi"),
					"storage": resource.MustParse("20Gi"),
				},
				Requests: corev1.ResourceList{
					"cpu":     resource.MustParse("1"),
					"memory":  resource.MustParse("150Mi"),
					"storage": resource.MustParse("10Gi"),
				},
			}

			cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{
				Spec: operatorv1.ManagementClusterConnectionSpec{
					GuardianDeployment: &operatorv1.GuardianDeployment{
						Spec: &operatorv1.GuardianDeploymentSpec{
							Template: &operatorv1.GuardianDeploymentPodTemplateSpec{
								Spec: &operatorv1.GuardianDeploymentPodSpec{
									Containers: []operatorv1.GuardianDeploymentContainer{{
										Name:      "tigera-guardian",
										Resources: &guardianResources,
									}},
								},
							},
						},
					},
				},
			}

			g := render.Guardian(cfg)
			resources, _ := g.Objects()
			Expect(resources).ToNot(BeNil())

			deployment, ok := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))

			Expect(container).NotTo(BeNil())
			Expect(container.Resources).To(Equal(guardianResources))
		})
	})
})
