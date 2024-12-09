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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

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

	createGuardianConfig := func(i operatorv1.InstallationSpec, addr string, openshift bool) *render.GuardianConfiguration {
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
			cfg = createGuardianConfig(i, "127.0.0.1:1234", false)
			g = render.Guardian(cfg)
			Expect(g.ResolveImages(nil)).To(BeNil())
			resources, _ = g.Objects()
		}

		BeforeEach(func() {
			renderGuardian(operatorv1.InstallationSpec{Registry: "my-reg/"})
		})

		It("should render all resources for a managed cluster", func() {
			expectedResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianServiceAccountName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianClusterRoleName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianClusterRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianServiceName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: ""}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianSecretName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceAccount, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.GuardianNamespace}},
			}

			rtest.ExpectResources(resources, expectedResources)

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

		It("should render toleration on GKE", func() {
			renderGuardian(operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
			})
			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment).NotTo(BeNil())
			Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
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

		renderGuardianPolicy := func(addr string, openshift bool) {
			cfg := createGuardianConfig(operatorv1.InstallationSpec{Registry: "my-reg/"}, addr, openshift)
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
					renderGuardianPolicy("127.0.0.1:1234", scenario.OpenShift)
					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: false}),
				Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: true}),
			)

			// The test matrix above validates against an IP-based management cluster address.
			// Validate policy adaptation for domain-based management cluster address here.
			It("should adapt Guardian policy if ManagementClusterAddr is domain-based", func() {
				renderGuardianPolicy("mydomain.io:8080", false)
				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				managementClusterEgressRule := policy.Spec.Egress[5]
				Expect(managementClusterEgressRule.Destination.Domains).To(Equal([]string{"mydomain.io"}))
				Expect(managementClusterEgressRule.Destination.Ports).To(Equal(networkpolicy.Ports(8080)))
			})
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
