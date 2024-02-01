// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package esgateway

import (
	"context"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

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
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("ES Gateway rendering tests", func() {
	Context("ES Gateway deployment", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *Config
		clusterDomain := "cluster.local"
		expectedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/es-gateway.json")
		expectedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/es-gateway_ocp.json")

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			replicas = 2
			kp, bundle := getTLS(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				ESGatewayKeyPair: kp,
				TrustedBundle:    bundle,
				KubeControllersUserSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				},
				ClusterDomain:   clusterDomain,
				EsAdminUserName: "elastic",
				UsePSP:          true,
				Namespace:       render.ElasticsearchNamespace,
				TruthNamespace:  common.OperatorNamespace(),
			}
		})

		It("should render an ES Gateway deployment and all supporting resources", func() {
			expectedResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: PolicyName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: ServiceAccountName, Namespace: render.ElasticsearchNamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: common.OperatorNamespace()}},
				&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-esgateway"}},
			}
			createResources, _ := EsGateway(cfg).Objects()
			rtest.ExpectResources(createResources, expectedResources)

			deploy, ok := rtest.GetResource(createResources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))

			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
		})

		It("should render an ES Gateway deployment and all supporting resources when CertificateManagement is enabled", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("", "", "", nil)
			Expect(err).NotTo(HaveOccurred())
			installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: secret.Data[corev1.TLSCertKey]}
			expectedResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: PolicyName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: ServiceAccountName, Namespace: render.ElasticsearchNamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: common.OperatorNamespace()}},
				&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-esgateway"}},
			}
			createResources, _ := EsGateway(cfg).Objects()
			rtest.ExpectResources(createResources, expectedResources)
		})

		It("should render properly when PSP is not supported by the cluster", func() {
			cfg.UsePSP = false
			component := EsGateway(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// Should not contain any PodSecurityPolicies
			for _, r := range resources {
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
			}
		})

		It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
			var replicas int32 = 1
			installation.ControlPlaneReplicas = &replicas

			component := EsGateway(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			var replicas int32 = 2
			installation.ControlPlaneReplicas = &replicas

			component := EsGateway(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
			Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity(DeploymentName, render.ElasticsearchNamespace)))
		})

		It("should apply controlPlaneNodeSelector correctly", func() {
			installation.ControlPlaneNodeSelector = map[string]string{"foo": "bar"}

			component := EsGateway(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should apply controlPlaneTolerations correctly", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			installation.ControlPlaneTolerations = []corev1.Toleration{t}
			component := EsGateway(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		})

		Context("allow-tigera rendering", func() {
			policyName := types.NamespacedName{Name: "allow-tigera.es-gateway-access", Namespace: "tigera-elasticsearch"}

			getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
				if scenario.ManagedCluster {
					return nil
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
					component := EsGateway(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				// ES Gateway only renders in the presence of an LogStorage CR and absence of a ManagementClusterConnection CR, therefore
				// does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
				Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			)
		})
		It("should set the right env when FIPS mode is enabled", func() {
			kp, bundle := getTLS(installation)
			enabled := operatorv1.FIPSModeEnabled
			installation.FIPSMode = &enabled
			component := EsGateway(&Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				ESGatewayKeyPair: kp,
				TrustedBundle:    bundle,
				KubeControllersUserSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				},
				ClusterDomain:   clusterDomain,
				EsAdminUserName: "elastic",
				Namespace:       render.ElasticsearchNamespace,
				TruthNamespace:  common.OperatorNamespace(),
			})

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "ES_GATEWAY_FIPS_MODE_ENABLED", Value: "true"}))
		})
	})
})

func getTLS(installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	esDNSNames := dns.GetServiceDNSNames(render.TigeraElasticsearchGatewaySecret, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	gwKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchGatewaySecret, render.ElasticsearchNamespace, esDNSNames)
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(gwKeyPair)
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

	return gwKeyPair, trustedBundle
}
