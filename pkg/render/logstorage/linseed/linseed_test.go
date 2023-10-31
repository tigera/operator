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

package linseed

import (
	"context"
	"fmt"

	"k8s.io/apiserver/pkg/authentication/serviceaccount"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage"

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
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

type resourceTestObj struct {
	name string
	ns   string
	typ  runtime.Object
	f    func(resource runtime.Object)
}

var _ = Describe("Linseed rendering tests", func() {
	Context("single-tenant rendering", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *Config
		clusterDomain := "cluster.local"
		expectedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/linseed.json")
		expectedPolicyWithDPI := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/linseed_dpi_enabled.json")
		expectedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/linseed_ocp.json")
		expectedPolicyForOpenshiftWithDPI := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/linseed_ocp_dpi_enabled.json")
		esClusterConfig := relasticsearch.NewClusterConfig("", 1, 1, 1)

		expectedResources := []resourceTestObj{
			{PolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
			{render.LinseedServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
			{ClusterRoleName, "", &rbacv1.ClusterRole{}, nil},
			{ClusterRoleName, "", &rbacv1.ClusterRoleBinding{}, nil},
			{ServiceAccountName, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
			{DeploymentName, render.ElasticsearchNamespace, &appsv1.Deployment{}, nil},
			{"tigera-linseed", "", &policyv1beta1.PodSecurityPolicy{}, nil},
		}

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}

			replicas = 2
			kp, tokenKP, bundle := getTLS(installation)

			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				KeyPair:         kp,
				TokenKeyPair:    tokenKP,
				TrustedBundle:   bundle,
				ClusterDomain:   clusterDomain,
				UsePSP:          true,
				ESClusterConfig: esClusterConfig,
				Namespace:       render.ElasticsearchNamespace,
				BindNamespaces:  []string{render.ElasticsearchNamespace},
				ElasticHost:     "tigera-secure-es-http.tigera-elasticsearch.svc",
				ElasticPort:     "9200",
			}
		})

		It("should render a Linseed deployment and all supporting resources", func() {
			component := Linseed(cfg)
			createResources, _ := component.Objects()
			compareResources(createResources, expectedResources, false)
		})

		It("should render Secrets RBAC permissions as part of ClusterRole", func() {
			component := Linseed(cfg)
			createResources, _ := component.Objects()
			cr := rtest.GetResource(createResources, ClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			secretsRules := rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch"},
			}
			Expect(cr.Rules).To(ContainElement(secretsRules))
		})

		It("should support an external elasticsearch endpoint", func() {
			cfg.ElasticHost = "test-host"
			cfg.ElasticPort = "443"
			cfg.ElasticClientSecret = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      logstorage.ExternalCertsSecret,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{
					"client.crt": {1, 2, 3},
					"client.key": {4, 5, 6},
				},
			}
			component := Linseed(cfg)
			createResources, _ := component.Objects()
			d, ok := rtest.GetResource(createResources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue(), "Deployment not found")

			// The deployment should have the hash annotation set, as well as a volume and volume mount for the client secret.
			Expect(d.Spec.Template.Annotations["hash.operator.tigera.io/elastic-client-secret"]).To(Equal("ae1a6776a81bf1fc0ee4aac936a90bd61a07aea7"))
			Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(corev1.Volume{
				Name: logstorage.ExternalCertsVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: logstorage.ExternalCertsSecret,
					},
				},
			}))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
				Name:      logstorage.ExternalCertsVolumeName,
				MountPath: "/certs/elasticsearch/mtls",
				ReadOnly:  true,
			}))

			// Should expect mTLS env vars set.
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "ELASTIC_CLIENT_KEY", Value: "/certs/elasticsearch/mtls/client.key",
			}))
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "ELASTIC_CLIENT_CERT", Value: "/certs/elasticsearch/mtls/client.crt",
			}))

			// The client secret should also be emitted as a resources, but copied to the destination namespace.
			s, ok := rtest.GetResource(createResources, logstorage.ExternalCertsSecret, render.ElasticsearchNamespace, "", "v1", "Secret").(*corev1.Secret)
			Expect(ok).To(BeTrue(), "Secret not copied")
			Expect(s.Data).To(Equal(cfg.ElasticClientSecret.Data))
		})

		It("should render properly when PSP is not supported by the cluster", func() {
			cfg.UsePSP = false
			component := Linseed(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// Should not contain any PodSecurityPolicies
			for _, r := range resources {
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
			}
		})

		It("should render a Linseed deployment and all supporting resources when CertificateManagement is enabled", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("", "", "", nil)
			Expect(err).NotTo(HaveOccurred())
			installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: secret.Data[corev1.TLSCertKey]}
			kp, tokenKP, bundle := getTLS(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				KeyPair:         kp,
				TokenKeyPair:    tokenKP,
				TrustedBundle:   bundle,
				ClusterDomain:   clusterDomain,
				UsePSP:          true,
				ESClusterConfig: esClusterConfig,
				Namespace:       render.ElasticsearchNamespace,
				BindNamespaces:  []string{render.ElasticsearchNamespace},
				ElasticHost:     "tigera-secure-es-http.tigera-elasticsearch.svc",
				ElasticPort:     "9200",
			}

			component := Linseed(cfg)

			createResources, _ := component.Objects()
			compareResources(createResources, expectedResources, true)
		})

		It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
			replicas = 1
			installation.ControlPlaneReplicas = &replicas

			component := Linseed(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue(), "Deployment not found")
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			installation.ControlPlaneReplicas = &replicas

			component := Linseed(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue(), "Deployment not found")
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
			Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity(DeploymentName, render.ElasticsearchNamespace)))
		})

		It("should apply controlPlaneNodeSelector correctly", func() {
			installation.ControlPlaneNodeSelector = map[string]string{"foo": "bar"}

			component := Linseed(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue(), "Deployment not found")
			Expect(d.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should apply controlPlaneTolerations correctly", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			installation.ControlPlaneTolerations = []corev1.Toleration{t}
			component := Linseed(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue(), "Deployment not found")
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		})

		Context("allow-tigera rendering", func() {
			policyName := types.NamespacedName{Name: "allow-tigera.linseed-access", Namespace: "tigera-elasticsearch"}

			getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
				if scenario.ManagedCluster {
					return nil
				}

				if scenario.DPIEnabled {
					return testutils.SelectPolicyByProvider(scenario, expectedPolicyWithDPI, expectedPolicyForOpenshiftWithDPI)
				}

				return testutils.SelectPolicyByProvider(scenario, expectedPolicy, expectedPolicyForOpenshift)
			}

			DescribeTable("should render allow-tigera policy",
				func(scenario testutils.AllowTigeraScenario) {
					if scenario.Openshift {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
					} else {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
					}
					cfg.HasDPIResource = scenario.DPIEnabled
					component := Linseed(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				// Linseed only renders in the presence of an LogStorage CR and absence of a ManagementClusterConnection CR, therefore
				// does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
				Entry("for management/standalone, kube-dns with dpi", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false, DPIEnabled: true}),
				Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
				Entry("for management/standalone, openshift-dns with dpi", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true, DPIEnabled: true}),
			)
		})

		It("should set the right env when FIPS mode is enabled", func() {
			kp, tokenKP, bundle := getTLS(installation)
			enabled := operatorv1.FIPSModeEnabled
			installation.FIPSMode = &enabled
			component := Linseed(&Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				KeyPair:         kp,
				TokenKeyPair:    tokenKP,
				TrustedBundle:   bundle,
				ClusterDomain:   clusterDomain,
				ESClusterConfig: esClusterConfig,
				Namespace:       render.ElasticsearchNamespace,
				BindNamespaces:  []string{render.ElasticsearchNamespace},
				ElasticHost:     "tigera-secure-es-http.tigera-elasticsearch.svc",
				ElasticPort:     "9200",
			})

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue(), "Deployment not found")
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "LINSEED_FIPS_MODE_ENABLED", Value: "true"}))
		})
	})

	Context("multi-tenant rendering", func() {
		var installation *operatorv1.InstallationSpec
		var tenant *operatorv1.Tenant
		var replicas int32
		var cfg *Config
		clusterDomain := "cluster.local"
		esClusterConfig := relasticsearch.NewClusterConfig("", 1, 1, 1)

		BeforeEach(func() {
			replicas = 2
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tenant",
				},
				Spec: operatorv1.TenantSpec{
					ID: "test-tenant",
					Indices: []operatorv1.Index{
						{
							BaseIndexName: "calico_alerts_standard",
							DataType:      "Alerts",
						},
						{
							BaseIndexName: "calico_auditlogs_standard",
							DataType:      "AuditLogs",
						},
						{
							BaseIndexName: "calico_bgplogs_standard",
							DataType:      "BGPLogs",
						},
						{
							BaseIndexName: "calico_compliance_reports_standard",
							DataType:      "ComplianceReports",
						},
						{
							BaseIndexName: "calico_compliance_benchmarks_standard",
							DataType:      "ComplianceBenchmarks",
						},
						{
							BaseIndexName: "calico_compliance_snapshots_standard",
							DataType:      "ComplianceSnapshots",
						},
						{
							BaseIndexName: "calico_dnslogs_standard",
							DataType:      "DNSLogs",
						},
						{
							BaseIndexName: "calico_flowlogs_standard",
							DataType:      "FlowLogs",
						},
						{
							BaseIndexName: "calico_l7logs_standard",
							DataType:      "L7Logs",
						},
						{
							BaseIndexName: "calico_runtime_reports_standard",
							DataType:      "RuntimeReports",
						},
						{
							BaseIndexName: "calico_threat_feeds_domain_set_standard",
							DataType:      "ThreatFeedsDomainSet",
						},
						{
							BaseIndexName: "calico_threat_feeds_ip_set_standard",
							DataType:      "ThreatFeedsIPSet",
						},
						{
							BaseIndexName: "calico_waflogs_standard",
							DataType:      "WAFLogs",
						},
					},
				},
			}
			kp, tokenKP, bundle := getTLS(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				KeyPair:         kp,
				TokenKeyPair:    tokenKP,
				TrustedBundle:   bundle,
				ClusterDomain:   clusterDomain,
				ESClusterConfig: esClusterConfig,
				Namespace:       "tenant-test-tenant",
				Tenant:          tenant,
				ElasticHost:     "tigera-secure-es-http.tigera-elasticsearch.svc",
				ElasticPort:     "9200",
			}
		})

		It("should render impersonation permissions as part of tigera-linseed ClusterRole", func() {
			component := Linseed(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			cr := rtest.GetResource(resources, ClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts"},
					Verbs:         []string{"impersonate"},
					ResourceNames: []string{render.LinseedServiceName},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"groups"},
					Verbs:     []string{"impersonate"},
					ResourceNames: []string{
						serviceaccount.AllServiceAccountsGroup,
						"system:authenticated",
						fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.ElasticsearchNamespace),
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
		})

		It("should render multi-tenant environment variables", func() {
			cfg.ManagementCluster = true
			component := Linseed(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, DeploymentName, cfg.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MANAGEMENT_OPERATOR_NS", Value: "tigera-operator"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "BACKEND", Value: "elastic-single-index"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_EXPECTED_TENANT_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", cfg.Tenant.Namespace)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_ALERTS_BASE_INDEX_NAME", Value: "calico_alerts_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_AUDIT_LOGS_BASE_INDEX_NAME", Value: "calico_auditlogs_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_COMPLIANCE_BENCHMARKS_BASE_INDEX_NAME", Value: "calico_compliance_benchmarks_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_COMPLIANCE_REPORTS_BASE_INDEX_NAME", Value: "calico_compliance_reports_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_COMPLIANCE_SNAPSHOTS_BASE_INDEX_NAME", Value: "calico_compliance_snapshots_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_BGP_LOGS_BASE_INDEX_NAME", Value: "calico_bgplogs_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_DNS_LOGS_BASE_INDEX_NAME", Value: "calico_dnslogs_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_FLOW_LOGS_BASE_INDEX_NAME", Value: "calico_flowlogs_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_L7_LOGS_BASE_INDEX_NAME", Value: "calico_l7logs_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_RUNTIME_REPORTS_BASE_INDEX_NAME", Value: "calico_runtime_reports_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_THREAT_FEEDS_DOMAIN_SET_BASE_INDEX_NAME", Value: "calico_threat_feeds_domain_set_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_THREAT_FEEDS_IP_SET_BASE_INDEX_NAME", Value: "calico_threat_feeds_ip_set_standard"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_WAF_LOGS_BASE_INDEX_NAME", Value: "calico_waflogs_standard"}))
		})
	})
})

func getTLS(installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	linseedDNSNames := dns.GetServiceDNSNames(render.TigeraLinseedSecret, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	linseedKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraLinseedSecret, render.ElasticsearchNamespace, linseedDNSNames)
	Expect(err).NotTo(HaveOccurred())

	tokenKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraLinseedTokenSecret, render.ElasticsearchNamespace, linseedDNSNames)
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(linseedKeyPair)
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

	return linseedKeyPair, tokenKeyPair, trustedBundle
}

func compareResources(resources []client.Object, expectedResources []resourceTestObj, useCSR bool) {
	Expect(resources).To(HaveLen(len(expectedResources)))
	for i, expectedResource := range expectedResources {
		resource := resources[i]
		actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
		actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()

		Expect(actualName).To(Equal(expectedResource.name), fmt.Sprintf("Rendered resource has wrong name (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(actualNS).To(Equal(expectedResource.ns), fmt.Sprintf("Rendered resource has wrong namespace (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(resource).Should(BeAssignableToTypeOf(expectedResource.typ))
		if expectedResource.f != nil {
			expectedResource.f(resource)
		}
	}

	// Check deployment
	deployment := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
	ExpectWithOffset(1, deployment).NotTo(BeNil())
	ExpectWithOffset(1, deployment.Spec.Strategy.Type).To(Equal(appsv1.RollingUpdateDeploymentStrategyType))
	ExpectWithOffset(1, deployment.Spec.Strategy.RollingUpdate.MaxSurge).To(Equal(ptr.IntOrStrPtr("100%")))
	ExpectWithOffset(1, deployment.Spec.Strategy.RollingUpdate.MaxUnavailable).To(Equal(ptr.IntOrStrPtr("0")))

	// Check containers
	expected := expectedContainers()
	actual := deployment.Spec.Template.Spec.Containers
	ExpectWithOffset(1, len(actual)).To(Equal(len(expected)))
	ExpectWithOffset(1, actual[0].Env).To(ConsistOf(expected[0].Env))
	ExpectWithOffset(1, actual[0].EnvFrom).To(ConsistOf(expected[0].EnvFrom))
	ExpectWithOffset(1, actual[0].VolumeMounts).To(ConsistOf(expected[0].VolumeMounts))
	ExpectWithOffset(1, actual[0].ReadinessProbe).To(Equal(expected[0].ReadinessProbe))
	ExpectWithOffset(1, actual[0].LivenessProbe).To(Equal(expected[0].LivenessProbe))
	ExpectWithOffset(1, actual[0].SecurityContext).To(Equal(expected[0].SecurityContext))
	ExpectWithOffset(1, actual[0].Name).To(Equal(expected[0].Name))
	ExpectWithOffset(1, actual[0].Resources).To(Equal(expected[0].Resources))
	ExpectWithOffset(1, actual[0].Image).To(Equal(expected[0].Image))
	ExpectWithOffset(1, actual[0].Ports).To(Equal(expected[0].Ports))
	ExpectWithOffset(1, actual).To(ConsistOf(expected))

	// Check init containers
	if useCSR {
		ExpectWithOffset(1, len(deployment.Spec.Template.Spec.InitContainers)).To(Equal(2))
		ExpectWithOffset(1, deployment.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", render.TigeraLinseedSecret)))
		ExpectWithOffset(1, deployment.Spec.Template.Spec.InitContainers[1].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", render.TigeraLinseedTokenSecret)))
	}

	// Check volumeMounts
	ExpectWithOffset(1, deployment.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVolumes(useCSR)))

	// Check annotations
	if !useCSR {
		ExpectWithOffset(1, deployment.Spec.Template.Annotations).To(HaveKeyWithValue("tigera-elasticsearch.hash.operator.tigera.io/tigera-secure-linseed-cert", Not(BeEmpty())))
	}
	ExpectWithOffset(1, deployment.Spec.Template.Annotations).To(HaveKeyWithValue("tigera-operator.hash.operator.tigera.io/tigera-ca-private", Not(BeEmpty())))

	// Check permissions
	clusterRole := rtest.GetResource(resources, ClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
	Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
		{
			APIGroups:     []string{"authorization.k8s.io"},
			Resources:     []string{"subjectaccessreviews"},
			ResourceNames: []string{},
			Verbs:         []string{"create"},
		},
		{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			ResourceNames: []string{"tigera-linseed"},
			Verbs:         []string{"use"},
		},
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"managedclusters"},
			Verbs:     []string{"list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}))
	clusterRoleBinding := rtest.GetResource(resources, ClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
	Expect(clusterRoleBinding.RoleRef.Name).To(Equal(ClusterRoleName))
	Expect(clusterRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      ServiceAccountName,
			Namespace: render.ElasticsearchNamespace,
		},
	}))

	// Check service
	service := rtest.GetResource(resources, render.LinseedServiceName, render.ElasticsearchNamespace, "", "v1", "Service").(*corev1.Service)
	Expect(service.Spec.Ports).To(ConsistOf([]corev1.ServicePort{
		{
			Name:       PortName,
			Port:       443,
			TargetPort: intstr.FromInt(TargetPort),
			Protocol:   corev1.ProtocolTCP,
		},
	}))
}

func expectedVolumes(useCSR bool) []corev1.Volume {
	var volumes []corev1.Volume
	if useCSR {
		volumes = append(volumes,
			corev1.Volume{
				Name: render.TigeraLinseedSecret,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			corev1.Volume{
				Name: "tigera-secure-linseed-token-tls",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		)
	} else {
		volumes = append(volumes,
			corev1.Volume{
				Name: render.TigeraLinseedSecret,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.TigeraLinseedSecret,
						DefaultMode: ptr.Int32ToPtr(420),
					},
				},
			},
			corev1.Volume{
				Name: "tigera-secure-linseed-token-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  "tigera-secure-linseed-token-tls",
						DefaultMode: ptr.Int32ToPtr(420),
					},
				},
			},
		)
	}

	volumes = append(volumes, corev1.Volume{
		Name: "tigera-ca-bundle",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "tigera-ca-bundle",
				},
			},
		},
	})
	return volumes
}

func expectedContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:            DeploymentName,
			ImagePullPolicy: render.ImagePullPolicy(),
			SecurityContext: &corev1.SecurityContext{
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				AllowPrivilegeEscalation: ptr.BoolToPtr(false),
				Privileged:               ptr.BoolToPtr(false),
				RunAsNonRoot:             ptr.BoolToPtr(true),
				RunAsGroup:               ptr.Int64ToPtr(10001),
				RunAsUser:                ptr.Int64ToPtr(10001),
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"/linseed", "-ready"},
					},
				},
				InitialDelaySeconds: 10,
			},
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"/linseed", "-live"},
					},
				},
				InitialDelaySeconds: 10,
			},
			Env: []corev1.EnvVar{
				{
					Name:  "LINSEED_LOG_LEVEL",
					Value: "INFO",
				},
				{
					Name:  "LINSEED_FIPS_MODE_ENABLED",
					Value: "false",
				},
				{
					Name:  "LINSEED_HTTPS_CERT",
					Value: "/tigera-secure-linseed-cert/tls.crt",
				},
				{
					Name:  "LINSEED_HTTPS_KEY",
					Value: "/tigera-secure-linseed-cert/tls.key",
				},
				{
					Name:  "LINSEED_CA_CERT",
					Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt",
				},
				{
					Name:  "ELASTIC_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_FLOWS_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_DNS_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_AUDIT_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_BGP_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_WAF_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_L7_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_RUNTIME_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_FLOWS_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_DNS_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_AUDIT_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_BGP_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_WAF_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_L7_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_RUNTIME_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_SCHEME",
					Value: "https",
				},
				{
					Name:  "ELASTIC_HOST",
					Value: "tigera-secure-es-http.tigera-elasticsearch.svc",
				},
				{
					Name:  "ELASTIC_PORT",
					Value: "9200",
				},
				{
					Name: "ELASTIC_USERNAME",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tigera-ee-linseed-elasticsearch-user-secret",
							},
							Key: "username",
						},
					},
				},
				{
					Name: "ELASTIC_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tigera-ee-linseed-elasticsearch-user-secret",
							},
							Key: "password",
						},
					},
				},
				{
					Name:  "ELASTIC_CA",
					Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt",
				},
				{
					Name:  "TOKEN_CONTROLLER_ENABLED",
					Value: "true",
				},
				{
					Name:  "LINSEED_TOKEN_KEY",
					Value: "/tigera-secure-linseed-token-tls/tls.key",
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "tigera-ca-bundle",
					MountPath: "/etc/pki/tls/certs",
					ReadOnly:  true,
				},
				{
					Name:      render.TigeraLinseedSecret,
					MountPath: "/tigera-secure-linseed-cert",
					ReadOnly:  true,
				},
				{
					Name:      "tigera-secure-linseed-token-tls",
					MountPath: "/tigera-secure-linseed-token-tls",
					ReadOnly:  true,
				},
			},
		},
	}
}
