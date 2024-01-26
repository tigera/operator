// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/common"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Policy recommendation rendering tests", func() {
	var (
		cfg     *render.PolicyRecommendationConfiguration
		bundle  certificatemanagement.TrustedBundle
		keyPair certificatemanagement.KeyPairInterface
		cli     client.Client
	)

	// Fetch expectations from utilities that require Ginkgo context.
	expectedUnmanagedPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/policyrecommendation.json")
	expectedUnmanagedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/policyrecommendation_ocp.json")

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())

		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle = certificateManager.CreateTrustedBundle()
		secretTLS, err := certificatemanagement.CreateSelfSignedSecret(render.PolicyRecommendationTLSSecretName, "", "", nil)
		Expect(err).NotTo(HaveOccurred())

		keyPair = certificatemanagement.NewKeyPair(secretTLS, []string{""}, "")

		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.PolicyRecommendationConfiguration{
			ClusterDomain:                  dns.DefaultClusterDomain,
			TrustedBundle:                  bundle,
			Installation:                   &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ManagedCluster:                 notManagedCluster,
			PolicyRecommendationCertSecret: keyPair,
			UsePSP:                         true,
			Namespace:                      render.PolicyRecommendationNamespace,
			BindingNamespaces:              []string{render.PolicyRecommendationNamespace},
		}
	})

	It("should render all resources for a default configuration", func() {
		cfg.Openshift = notOpenshift
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-policy-recommendation", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-policy-recommendation", ns: "tigera-policy-recommendation", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "allow-tigera.default-deny", ns: "tigera-policy-recommendation", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "allow-tigera.tigera-policy-recommendation", ns: "tigera-policy-recommendation", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "tigera-policy-recommendation", ns: "tigera-policy-recommendation", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-policy-recommendation", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// Should mount ManagerTLSSecret for non-managed clusters
		prc := rtest.GetResource(resources, render.PolicyRecommendationName, render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(prc.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(prc.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			corev1.EnvVar{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/policy-recommendation-tls/tls.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/policy-recommendation-tls/tls.key"},
			corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: "https://tigera-manager.tigera-manager.svc:9443"},
		))
		Expect(prc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(prc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))

		Expect(prc.Spec.Template.Spec.Volumes[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(prc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))

		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))

		clusterRole := rtest.GetResource(resources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys", "managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
					"policyrecommendationscopes",
					"policyrecommendationscopes/status",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"globalnetworksets",
				},
				Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
		))

		clusterRoleBinding := rtest.GetResource(resources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef).To(Equal(
			rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     render.PolicyRecommendationName,
			}))
		Expect(clusterRoleBinding.Subjects).To(ConsistOf(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      render.PolicyRecommendationName,
				Namespace: render.PolicyRecommendationNamespace,
			}))
	})

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := render.PolicyRecommendation(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
		}
	})

	It("should apply controlPlaneNodeSelector correctly", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
		}
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should apply controlPlaneTolerations correctly", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
	})

	It("should render an init container when certificate management is enabled", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		policyRecommendationCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.PolicyRecommendationTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.PolicyRecommendationCertSecret = policyRecommendationCertSecret

		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()

		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := idc.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.PolicyRecommendationTLSSecretName)))
	})

	It("should override container's resource request with the value from policy recommendation CR", func() {
		prResources := corev1.ResourceRequirements{
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

		policyRecommendationcfg := operatorv1.PolicyRecommendation{
			Spec: operatorv1.PolicyRecommendationSpec{
				PolicyRecommendationDeployment: &operatorv1.PolicyRecommendationDeployment{
					Spec: &operatorv1.PolicyRecommendationDeploymentSpec{
						Template: &operatorv1.PolicyRecommendationDeploymentPodTemplateSpec{
							Spec: &operatorv1.PolicyRecommendationDeploymentPodSpec{
								Containers: []operatorv1.PolicyRecommendationDeploymentContainer{{
									Name:      "policy-recommendation-controller",
									Resources: &prResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.PolicyRecommendation = &policyRecommendationcfg
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		d, ok := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("policy-recommendation-controller"))
		Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(prResources))
	})

	It("should override init container's resource request with the value from policy recommendation CR", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		prResources := corev1.ResourceRequirements{
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

		policyRecommendationcfg := operatorv1.PolicyRecommendation{
			Spec: operatorv1.PolicyRecommendationSpec{
				PolicyRecommendationDeployment: &operatorv1.PolicyRecommendationDeployment{
					Spec: &operatorv1.PolicyRecommendationDeploymentSpec{
						Template: &operatorv1.PolicyRecommendationDeploymentPodTemplateSpec{
							Spec: &operatorv1.PolicyRecommendationDeploymentPodSpec{
								InitContainers: []operatorv1.PolicyRecommendationDeploymentInitContainer{{
									Name:      "policy-recommendation-tls-key-cert-provisioner",
									Resources: &prResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.PolicyRecommendation = &policyRecommendationcfg
		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		policyRecommendationCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.PolicyRecommendationTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.PolicyRecommendationCertSecret = policyRecommendationCertSecret

		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()

		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(idc.Spec.Template.Spec.InitContainers[0].Name).To(Equal("policy-recommendation-tls-key-cert-provisioner"))
		Expect(idc.Spec.Template.Spec.InitContainers[0].Resources).To(Equal(prResources))
	})

	Context("allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.tigera-policy-recommendation", Namespace: "tigera-policy-recommendation"}

		getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			return testutils.SelectPolicyByClusterTypeAndProvider(
				scenario,
				expectedUnmanagedPolicy,
				expectedUnmanagedPolicyForOpenshift,
				nil,
				nil,
			)
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.ManagedCluster = scenario.ManagedCluster
				cfg.Openshift = scenario.Openshift
				component := render.PolicyRecommendation(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
		)
	})

	Context("multi-tenant rendering", func() {
		tenantANamespace := "tenant-a"
		tenantBNamespace := "tenant-b"
		It("should render expected components inside expected namespace for each policyrecommendation instance", func() {
			cfg.Namespace = tenantANamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.BindingNamespaces = []string{tenantANamespace}
			cfg.ExternalElastic = true
			tenantAPolicyRec := render.PolicyRecommendation(cfg)

			tenantAResources, _ := tenantAPolicyRec.Objects()

			// Should render the correct resources.
			tenantAExpectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{name: tenantANamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
				{name: "tigera-policy-recommendation", ns: tenantANamespace, group: "", version: "v1", kind: "ServiceAccount"},
				{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
				{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
				{name: "allow-tigera.default-deny", ns: tenantANamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
				{name: "tigera-policy-recommendation-managed-cluster-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
				{name: "tigera-policy-recommendation-managed-cluster-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
				{name: "allow-tigera.tigera-policy-recommendation", ns: tenantANamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
				{name: "tigera-policy-recommendation", ns: tenantANamespace, group: "apps", version: "v1", kind: "Deployment"},
				{name: "tigera-policy-recommendation", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			}

			Expect(len(tenantAResources)).To(Equal(len(tenantAExpectedResources)))

			for i, expectedRes := range tenantAExpectedResources {
				rtest.ExpectResourceTypeAndObjectMetadata(tenantAResources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			d := rtest.GetResource(tenantAResources, "tigera-policy-recommendation", tenantANamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: tenantANamespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "tenant-a-id"}))

			cfg.Namespace = tenantBNamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantB",
					Namespace: tenantBNamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-b-id",
				},
			}
			cfg.BindingNamespaces = []string{tenantANamespace, tenantBNamespace}
			tenantBPolicyRec := render.PolicyRecommendation(cfg)

			tenantBResources, _ := tenantBPolicyRec.Objects()

			// Should render the correct resources.
			tenantBExpectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{name: tenantBNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
				{name: "tigera-policy-recommendation", ns: tenantBNamespace, group: "", version: "v1", kind: "ServiceAccount"},
				{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
				{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
				{name: "allow-tigera.default-deny", ns: tenantBNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
				{name: "tigera-policy-recommendation-managed-cluster-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
				{name: "tigera-policy-recommendation-managed-cluster-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
				{name: "allow-tigera.tigera-policy-recommendation", ns: tenantBNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
				{name: "tigera-policy-recommendation", ns: tenantBNamespace, group: "apps", version: "v1", kind: "Deployment"},
				{name: "tigera-policy-recommendation", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			}

			Expect(len(tenantBResources)).To(Equal(len(tenantBExpectedResources)))
			for i, expectedRes := range tenantBExpectedResources {
				rtest.ExpectResourceTypeAndObjectMetadata(tenantBResources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			d = rtest.GetResource(tenantBResources, "tigera-policy-recommendation", tenantBNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs = d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: tenantBNamespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "tenant-b-id"}))
		})

		It("should render environment variables per tenant", func() {
			cfg.Namespace = tenantANamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.ExternalElastic = true
			cfg.BindingNamespaces = []string{tenantANamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			d := rtest.GetResource(createdResources, "tigera-policy-recommendation", cfg.Tenant.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: cfg.Tenant.Namespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", cfg.Tenant.Namespace)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", cfg.Tenant.Namespace)}))
		})

		It("should render environment variables for a single tenant external elastic", func() {
			cfg.Namespace = render.PolicyRecommendationNamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenantA",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.ExternalElastic = true
			cfg.BindingNamespaces = []string{render.PolicyRecommendationNamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			d := rtest.GetResource(createdResources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", render.ManagerNamespace)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", render.ElasticsearchNamespace)}))
		})

		It("should render environment variables for a single tenant internal elastic", func() {
			cfg.Namespace = render.PolicyRecommendationNamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenantA",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.ExternalElastic = false
			cfg.BindingNamespaces = []string{render.PolicyRecommendationNamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			d := rtest.GetResource(createdResources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", render.ManagerNamespace)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", render.ElasticsearchNamespace)}))
		})

		It("should render RBAC per tenant", func() {
			cfg.Namespace = tenantANamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.BindingNamespaces = []string{tenantANamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			// Check that the cluster role allows the tenant's service account to impersonate
			clusterRole := rtest.GetResource(createdResources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			clusterRoleBinding := rtest.GetResource(createdResources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(clusterRole.Rules).To(ContainElements(
				rbacv1.PolicyRule{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts"},
					Verbs:         []string{"impersonate"},
					ResourceNames: []string{render.PolicyRecommendationName},
				},
				rbacv1.PolicyRule{
					APIGroups: []string{""},
					Resources: []string{"groups"},
					Verbs:     []string{"impersonate"},
					ResourceNames: []string{
						serviceaccount.AllServiceAccountsGroup,
						"system:authenticated",
						fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.PolicyRecommendationNamespace),
					},
				},
			))
			Expect(clusterRoleBinding.RoleRef).To(Equal(
				rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     render.PolicyRecommendationName,
				}))
			Expect(clusterRoleBinding.Subjects).To(ConsistOf(
				rbacv1.Subject{
					Kind:      "ServiceAccount",
					Name:      render.PolicyRecommendationName,
					Namespace: cfg.Tenant.Namespace,
				}))

			// Check that the cluster role allows the tigera-policy-recommendation from namesapce tigera-policy-recommendation
			// to get managed clusters in order to bypass the authentication proxy in Voltron
			clusterRoleManagedClusters := rtest.GetResource(createdResources, render.PolicyRecommendationMultiTenantManagedClustersAccessClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(clusterRoleManagedClusters.Rules).To(ContainElements(
				rbacv1.PolicyRule{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs:     []string{"get"},
				},
			))
			clusterRoleManagedClustersBinding := rtest.GetResource(createdResources, render.PolicyRecommendationMultiTenantManagedClustersAccessClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(clusterRoleManagedClustersBinding.RoleRef).To(Equal(
				rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     render.PolicyRecommendationMultiTenantManagedClustersAccessClusterRoleName,
				}))
			Expect(clusterRoleManagedClustersBinding.Subjects).To(ConsistOf(
				rbacv1.Subject{
					Kind:      "ServiceAccount",
					Name:      render.PolicyRecommendationName,
					Namespace: render.PolicyRecommendationNamespace,
				}))
		})
	})
})
