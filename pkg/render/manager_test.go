// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Tigera Secure Manager rendering tests", func() {
	var replicas int32 = 2
	installation := &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas}
	compliance := &operatorv1.Compliance{}

	expectedManagerPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/manager.json")
	expectedManagerOpenshiftPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/manager_ocp.json")

	It("should render all resources for a default configuration", func() {
		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		// Should render the correct resources.
		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		// deployment
		Expect(deployment.Spec.Template.Spec.Volumes).To(HaveLen(3))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[1].VolumeSource.ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(3))
		manager := deployment.Spec.Template.Spec.Containers[0]
		esProxy := deployment.Spec.Template.Spec.Containers[1]
		voltron := deployment.Spec.Template.Spec.Containers[2]

		Expect(manager.Image).Should(Equal(components.TigeraRegistry + "tigera/cnx-manager:" + components.ComponentManager.Version))
		Expect(esProxy.Image).Should(Equal(components.TigeraRegistry + "tigera/es-proxy:" + components.ComponentEsProxy.Version))
		Expect(voltron.Image).Should(Equal(components.TigeraRegistry + "tigera/voltron:" + components.ComponentManagerProxy.Version))

		// manager container
		Expect(*manager.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*manager.SecurityContext.Privileged).To(BeFalse())
		Expect(*manager.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*manager.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*manager.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(manager.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(manager.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		Expect(manager.Env).Should(ContainElements(
			corev1.EnvVar{Name: "ENABLE_COMPLIANCE_REPORTS", Value: "true"},
			corev1.EnvVar{Name: "CNX_POLICY_RECOMMENDATION_SUPPORT", Value: "true"},
		))

		// es-proxy container
		Expect(esProxy.Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/internal-manager-tls/tls.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/internal-manager-tls/tls.key"},
			corev1.EnvVar{Name: "VOLTRON_URL", Value: "https://tigera-manager.tigera-manager.svc:9443"},
		))

		Expect(esProxy.VolumeMounts).To(HaveLen(2))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(esProxy.VolumeMounts[1].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(esProxy.VolumeMounts[1].MountPath).To(Equal("/internal-manager-tls"))

		Expect(*esProxy.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*esProxy.SecurityContext.Privileged).To(BeFalse())
		Expect(*esProxy.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*esProxy.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*esProxy.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(esProxy.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(esProxy.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// voltron container
		Expect(voltron.Env).To(ContainElements([]corev1.EnvVar{
			{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: "true"},
			{Name: "VOLTRON_QUERYSERVER_ENDPOINT", Value: "https://tigera-api.tigera-system.svc:8080"},
			{Name: "VOLTRON_QUERYSERVER_BASE_PATH", Value: "/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy/"},
			{Name: "VOLTRON_QUERYSERVER_CA_BUNDLE_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "VOLTRON_LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc.cluster.local"},
		}))

		Expect(voltron.VolumeMounts).To(HaveLen(2))
		Expect(voltron.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))

		Expect(*voltron.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*voltron.SecurityContext.Privileged).To(BeFalse())
		Expect(*voltron.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*voltron.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*voltron.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(voltron.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(voltron.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// Check the namespace.
		ns := rtest.GetResource(resources, "tigera-manager", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(ns.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
		Expect(ns.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		resources := renderObjects(renderConfig{oidc: false, managementCluster: nil, installation: &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas, KubernetesProvider: operatorv1.ProviderOpenShift}, compliance: compliance, complianceFeatureActive: true})

		// tigera-manager-role clusterRole should have openshift securitycontextconstraints PolicyRule
		managerRole := rtest.GetResource(resources, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(managerRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	type managerComplianceExpectation struct {
		managerFlag bool
		voltronFlag bool
	}
	DescribeTable("should set container env appropriately when compliance is not fully available",
		func(crPresent bool, licenseFeatureActive bool, scenario managerComplianceExpectation) {
			var complianceCR *operatorv1.Compliance
			if crPresent {
				complianceCR = &operatorv1.Compliance{}
			}

			resources := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              complianceCR,
				complianceFeatureActive: licenseFeatureActive,
				ns:                      render.ManagerNamespace,
			})

			deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			manager := deployment.Spec.Template.Spec.Containers[0]
			voltron := deployment.Spec.Template.Spec.Containers[2]
			Expect(manager.Env).To(ContainElement(corev1.EnvVar{Name: "ENABLE_COMPLIANCE_REPORTS", Value: strconv.FormatBool(scenario.managerFlag)}))
			Expect(voltron.Env).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: strconv.FormatBool(scenario.voltronFlag)}))
		},
		Entry("Both CR and license feature not present/active", false, false, managerComplianceExpectation{managerFlag: false, voltronFlag: false}),
		Entry("CR not present, license feature active", false, true, managerComplianceExpectation{managerFlag: false, voltronFlag: false}),

		// We expect the manager feature flag to be true in this case, since the CR is present. The manager will render an insufficient license state.
		Entry("CR present, license feature not active", true, false, managerComplianceExpectation{managerFlag: true, voltronFlag: false}),
	)

	It("should render the correct ClusterRole", func() {
		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		clusterRole := rtest.GetResource(resources, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
			{
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-manager"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"l7flows",
					"l7logs",
					"events",
					"processes",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
		}))
	})

	It("should set OIDC Authority environment when auth-type is OIDC", func() {
		resources := renderObjects(renderConfig{
			oidc:                    true,
			managementCluster:       nil,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		d := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d).NotTo(BeNil())

		oidcEnvVar := corev1.EnvVar{
			Name:      "CNX_WEB_OIDC_AUTHORITY",
			Value:     "https://127.0.0.1/dex",
			ValueFrom: nil,
		}
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(oidcEnvVar))
	})

	Describe("public ca bundle", func() {
		var cfg *render.ManagerConfiguration
		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			cli := fake.NewClientBuilder().WithScheme(scheme).Build()

			certificateManager, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			tunnelSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.VoltronTunnelSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			internalTraffic, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			managerTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerTLSSecretName, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())

			voltronLinseedCert, err := certificateManager.GetOrCreateKeyPair(cli, render.VoltronLinseedTLS, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			cfg = &render.ManagerConfiguration{
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(certificateManager.KeyPair()),
				TLSKeyPair:            managerTLS,
				ManagementCluster:     &operatorv1.ManagementCluster{},
				TunnelServerCert:      tunnelSecret,
				VoltronLinseedKeyPair: voltronLinseedCert,
				InternalTLSKeyPair:    internalTraffic,
				Installation:          installation,
				ClusterConfig:         &relasticsearch.ClusterConfig{},
				Namespace:             render.ManagerNamespace,
				TruthNamespace:        common.OperatorNamespace(),
			}
		})

		It("should render when disabled", func() {
			resources, err := render.Manager(cfg)
			Expect(err).ToNot(HaveOccurred())
			rs, _ := resources.Objects()

			managerDeployment := rtest.GetResource(rs, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			voltronContainer := rtest.GetContainer(managerDeployment.Spec.Template.Spec.Containers, "tigera-voltron")

			rtest.ExpectEnv(voltronContainer.Env, "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", "false")
		})

		It("should render when enabled", func() {
			cfg.ManagementCluster.Spec.TLS = &operatorv1.TLS{SecretName: render.ManagerTLSSecretName}

			resources, err := render.Manager(cfg)
			Expect(err).ToNot(HaveOccurred())
			rs, _ := resources.Objects()

			managerDeployment := rtest.GetResource(rs, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			voltronContainer := rtest.GetContainer(managerDeployment.Spec.Template.Spec.Containers, "tigera-voltron")

			rtest.ExpectEnv(voltronContainer.Env, "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", "true")
		})
	})

	It("should render multicluster settings properly", func() {
		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       &operatorv1.ManagementCluster{},
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		// Should render the correct resources.
		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.VoltronLinseedPublicCert, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		By("configuring the manager deployment")
		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		manager := deployment.Spec.Template.Spec.Containers[0]
		Expect(manager.Name).To(Equal("tigera-manager"))
		rtest.ExpectEnv(manager.Env, "ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		voltron := deployment.Spec.Template.Spec.Containers[2]
		esProxy := deployment.Spec.Template.Spec.Containers[1]
		Expect(voltron.Name).To(Equal("tigera-voltron"))
		rtest.ExpectEnv(voltron.Env, "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		Expect(esProxy.VolumeMounts).To(HaveLen(2))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(esProxy.VolumeMounts[1].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(esProxy.VolumeMounts[1].MountPath).To(Equal("/internal-manager-tls"))

		Expect(len(voltron.VolumeMounts)).To(Equal(5))
		Expect(voltron.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/internal-manager-tls"))
		Expect(voltron.VolumeMounts[3].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(voltron.VolumeMounts[3].MountPath).To(Equal("/tigera-management-cluster-connection"))
		Expect(voltron.VolumeMounts[4].Name).To(Equal(render.VoltronLinseedTLS))
		Expect(voltron.VolumeMounts[4].MountPath).To(Equal("/tigera-voltron-linseed-tls"))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(5))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[1].VolumeSource.ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Secret.SecretName).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Name).To(Equal(render.VoltronLinseedTLS))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Secret.SecretName).To(Equal(render.VoltronLinseedTLS))

		clusterRole := rtest.GetResource(resources, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-manager"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"l7flows",
					"l7logs",
					"events",
					"processes",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
		}))
	})

	var kp certificatemanagement.KeyPairInterface
	var internalKp certificatemanagement.KeyPairInterface
	var voltronLinseedKP certificatemanagement.KeyPairInterface
	var bundle certificatemanagement.TrustedBundle

	BeforeEach(func() {
		var err error
		secret, err := certificatemanagement.CreateSelfSignedSecret(render.ManagerTLSSecretName, common.OperatorNamespace(), render.ManagerTLSSecretName, nil)
		Expect(err).NotTo(HaveOccurred())

		kp = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())

		internalKp = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())

		voltronLinseedKP = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle = certificateManager.CreateTrustedBundle()
	})

	// renderManager passes in as few parameters as possible to render.Manager without it
	// panicing. It accepts variations on the installspec for testing purposes.
	renderManager := func(i *operatorv1.InstallationSpec) *appsv1.Deployment {
		cfg := &render.ManagerConfiguration{
			TrustedCertBundle:     bundle,
			ClusterConfig:         &relasticsearch.ClusterConfig{},
			TLSKeyPair:            kp,
			VoltronLinseedKeyPair: voltronLinseedKP,
			Installation:          i,
			ESLicenseType:         render.ElasticsearchLicenseTypeUnknown,
			Replicas:              &replicas,
			UsePSP:                true,
			InternalTLSKeyPair:    internalKp,
			Namespace:             render.ManagerNamespace,
			TruthNamespace:        common.OperatorNamespace(),
		}
		component, err := render.Manager(cfg)
		Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
		resources, _ := component.Objects()
		return rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
	}

	It("should apply controlPlaneNodeSelectors", func() {
		deployment := renderManager(&operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{
				"foo": "bar",
			},
			ControlPlaneReplicas: &replicas,
		})
		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should apply controlPlaneTolerations", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		deployment := renderManager(&operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
			ControlPlaneReplicas:    &replicas,
		})
		Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateCriticalAddonsAndControlPlane, t)))
	})

	It("should render all resources for certificate management", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes()
		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{CertificateManagement: &operatorv1.CertificateManagement{CACert: cert}, ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(deployment.Spec.Template.Spec.InitContainers).To(HaveLen(2))
		managerCSRInitContainer := deployment.Spec.Template.Spec.InitContainers[0]
		internalManagerCSRInitContainer := deployment.Spec.Template.Spec.InitContainers[1]
		Expect(managerCSRInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ManagerTLSSecretName)))
		Expect(internalManagerCSRInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ManagerInternalTLSSecretName)))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(3))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret).To(BeNil())
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret).To(BeNil())
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		installation.ControlPlaneReplicas = &replicas

		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		deploy, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		installation.ControlPlaneReplicas = &replicas

		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		deploy, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-manager", render.ManagerNamespace)))
	})

	It("should set the right env when FIPS is enabled", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		installation.FIPSMode = &fipsEnabled
		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		deployment, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deployment.Spec.Template.Spec.Containers[0].Name).To(Equal("tigera-manager"))
		Expect(deployment.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-es-proxy"))
		Expect(deployment.Spec.Template.Spec.Containers[2].Name).To(Equal("tigera-voltron"))
		Expect(deployment.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "ENABLE_KIBANA", Value: "false"}))
		Expect(deployment.Spec.Template.Spec.Containers[1].Env).To(ContainElement(corev1.EnvVar{Name: "FIPS_MODE_ENABLED", Value: "true"}))
		Expect(deployment.Spec.Template.Spec.Containers[2].Env).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_FIPS_MODE_ENABLED", Value: "true"}))
	})

	Context("allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.manager-access", Namespace: "tigera-manager"}

		getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if scenario.ManagedCluster {
				return nil
			}

			return testutils.SelectPolicyByProvider(scenario, expectedManagerPolicy, expectedManagerOpenshiftPolicy)
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				// Default configuration.
				resources := renderObjects(renderConfig{
					openshift:               scenario.OpenShift,
					oidc:                    false,
					managementCluster:       nil,
					installation:            installation,
					compliance:              compliance,
					complianceFeatureActive: true,
					ns:                      render.ManagerNamespace,
				})

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				if expectedPolicy != nil {
					// Check fields individuall before checking the entire struct so that we get
					// more useful failure messages.
					Expect(policy.ObjectMeta).To(Equal(expectedPolicy.ObjectMeta))
					Expect(policy.Spec.Ingress).To(ConsistOf(expectedPolicy.Spec.Ingress))
					Expect(policy.Spec.Egress).To(ConsistOf(expectedPolicy.Spec.Egress))
					Expect(policy.Spec.Selector).To(Equal(expectedPolicy.Spec.Selector))
					Expect(policy.Spec.Order).To(Equal(expectedPolicy.Spec.Order))
					Expect(policy.Spec.Tier).To(Equal(expectedPolicy.Spec.Tier))
					Expect(policy.Spec.Types).To(Equal(expectedPolicy.Spec.Types))
					Expect(policy.Spec.ServiceAccountSelector).To(Equal(expectedPolicy.Spec.ServiceAccountSelector))
				}
				Expect(policy).To(Equal(expectedPolicy))
			},
			// Manager only renders in the presence of a Manager CR, therefore does not have a config option for managed clusters.
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: true}),
		)
	})

	Context("multi-tenant rendering", func() {
		tenantANamespace := "tenant-a"
		tenantBNamespace := "tenant-b"

		It("should render expected components inside expected namespace for each manager instance", func() {
			tenantAResources := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantANamespace,
			})

			expectedTenantAResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
				&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"}},
			}
			rtest.ExpectResources(tenantAResources, expectedTenantAResources)

			tenantBResources := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantBNamespace,
			})

			expectedTenantBResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
				&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"}},
			}
			rtest.ExpectResources(tenantBResources, expectedTenantBResources)
		})

		It("should render cluster role binding with tenant namespaces as subjects", func() {
			resources := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantBNamespace,
				bindingNamespaces:       []string{tenantANamespace, tenantBNamespace},
			})

			crb := rtest.GetResource(resources, render.ManagerClusterRoleBinding, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(crb.Subjects).To(Equal([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ManagerServiceAccount,
					Namespace: tenantANamespace,
				},
				{
					Kind:      "ServiceAccount",
					Name:      render.ManagerServiceAccount,
					Namespace: tenantBNamespace,
				},
			}))
		})

		It("should render multi-tenant environment variables", func() {
			tenantAResources := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantANamespace,
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenant",
						Namespace: tenantANamespace,
					},
					Spec: operatorv1.TenantSpec{
						ID: "tenant-a",
					},
				},
			})
			d := rtest.GetResource(tenantAResources, "tigera-manager", tenantANamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[2].Env
			esProxyEnv := d.Spec.Template.Spec.Containers[1].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_NAMESPACE", Value: tenantANamespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_ID", Value: "tenant-a"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_REQUIRE_TENANT_CLAIM", Value: "true"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", tenantANamespace)}))
			Expect(esProxyEnv).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_URL", Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", tenantANamespace)}))
		})
	})
})

type renderConfig struct {
	oidc                    bool
	managementCluster       *operatorv1.ManagementCluster
	installation            *operatorv1.InstallationSpec
	compliance              *operatorv1.Compliance
	complianceFeatureActive bool
	openshift               bool
	ns                      string
	bindingNamespaces       []string
	tenant                  *operatorv1.Tenant
}

func renderObjects(roc renderConfig) []client.Object {
	var dexCfg authentication.KeyValidatorConfig
	if roc.oidc {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"},
			},
		}

		dexCfg = render.NewDexKeyValidatorConfig(authentication, nil, dns.DefaultClusterDomain)
	}

	var tunnelSecret certificatemanagement.KeyPairInterface
	var internalTraffic certificatemanagement.KeyPairInterface
	var voltronLinseedKP certificatemanagement.KeyPairInterface

	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, roc.installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	bundle := certificatemanagement.CreateTrustedBundle(certificateManager.KeyPair())

	if roc.managementCluster != nil {
		tunnelSecret, err = certificateManager.GetOrCreateKeyPair(cli, render.VoltronTunnelSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		voltronLinseedKP, err = certificateManager.GetOrCreateKeyPair(cli, render.VoltronLinseedTLS, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())

	}
	managerTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerTLSSecretName, common.OperatorNamespace(), []string{""})
	Expect(err).NotTo(HaveOccurred())
	internalTraffic, err = certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
	Expect(err).NotTo(HaveOccurred())

	if len(roc.bindingNamespaces) == 0 {
		roc.bindingNamespaces = []string{roc.ns}
	}

	esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
	cfg := &render.ManagerConfiguration{
		KeyValidatorConfig:      dexCfg,
		TrustedCertBundle:       bundle,
		ClusterConfig:           esConfigMap,
		TLSKeyPair:              managerTLS,
		Installation:            roc.installation,
		ManagementCluster:       roc.managementCluster,
		TunnelServerCert:        tunnelSecret,
		VoltronLinseedKeyPair:   voltronLinseedKP,
		InternalTLSKeyPair:      internalTraffic,
		ClusterDomain:           dns.DefaultClusterDomain,
		ESLicenseType:           render.ElasticsearchLicenseTypeEnterpriseTrial,
		Replicas:                roc.installation.ControlPlaneReplicas,
		Compliance:              roc.compliance,
		ComplianceLicenseActive: roc.complianceFeatureActive,
		OpenShift:               roc.openshift,
		UsePSP:                  true,
		Namespace:               roc.ns,
		BindingNamespaces:       roc.bindingNamespaces,
		TruthNamespace:          common.OperatorNamespace(),
		Tenant:                  roc.tenant,
	}
	component, err := render.Manager(cfg)
	Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
	Expect(component.ResolveImages(nil)).To(BeNil())
	resources, _ := component.Objects()
	return resources
}
