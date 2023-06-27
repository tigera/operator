// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("dex rendering tests", func() {
	const clusterName = "svc.cluster.local"

	expectedDexPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/dex.json")
	expectedDexOpenshiftPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/dex_ocp.json")

	Context("dex is configured for oidc", func() {

		const (
			rbac           = "rbac.authorization.k8s.io"
			pullSecretName = "tigera-pull-secret"
		)

		var (
			authentication *operatorv1.Authentication
			dexSecret      *corev1.Secret
			idpSecret      *corev1.Secret
			pullSecrets    []*corev1.Secret
			replicas       int32
			cfg            *render.DexComponentConfiguration
		)

		var expectedVolumeMounts = []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/dex/baseCfg", ReadOnly: true},
			{Name: "secrets", MountPath: "/etc/dex/secrets", ReadOnly: true},
			{Name: "tigera-dex-tls", MountPath: "/tigera-dex-tls", ReadOnly: true},
			{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/certs", ReadOnly: true},
			{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/cert.pem", SubPath: "ca-bundle.crt", ReadOnly: true},
		}

		var expectedVolumes = []corev1.Volume{
			{Name: "config",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-dex",
						},
						Items: []corev1.KeyToPath{
							{Key: "config.yaml", Path: "config.yaml"},
						},
					},
				}},
			{Name: "secrets",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: "tigera-oidc-credentials",
						Items: []corev1.KeyToPath{
							{Key: "serviceAccountSecret", Path: "google-groups.json"},
						},
						DefaultMode: ptr.Int32ToPtr(420),
					},
				}},
			{Name: "tigera-dex-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  "tigera-dex-tls",
						DefaultMode: ptr.Int32ToPtr(420),
					},
				}},
			{Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-ca-bundle",
						},
						Items: []corev1.KeyToPath{
							{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: certificatemanagement.TrustedCertConfigMapKeyName},
							{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: "ca.pem"},
							{Key: certificatemanagement.RHELRootCertificateBundleName, Path: certificatemanagement.RHELRootCertificateBundleName},
						},
					},
				}},
		}

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			cli := fake.NewClientBuilder().WithScheme(scheme).Build()
			certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			dnsNames := dns.GetServiceDNSNames(render.DexObjectName, render.DexNamespace, clusterDomain)
			tlsKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.DexTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).NotTo(HaveOccurred())
			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
			}

			authentication = &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:       "https://example.com",
						UsernameClaim:   "email",
						GroupsClaim:     "group",
						RequestedScopes: []string{"scope"},
					},
				},
			}

			dexSecret = render.CreateDexClientSecret()
			idpSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.OIDCSecretName,
					Namespace: common.OperatorNamespace(),
				},
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				Data: map[string][]byte{
					"adminEmail":           []byte("a@b.com"),
					"clientID":             []byte("a.b.com"),
					"clientSecret":         []byte("my-secret"),
					"serviceAccountSecret": []byte("my-secret2"),
				}}
			pullSecrets = []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pullSecretName,
						Namespace: common.OperatorNamespace(),
					},
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				}}

			replicas = 2

			dexCfg := render.NewDexConfig(installation.CertificateManagement, authentication, dexSecret, idpSecret, clusterName)
			trustedCaBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
			Expect(err).NotTo(HaveOccurred())

			cfg = &render.DexComponentConfiguration{
				PullSecrets:   pullSecrets,
				Installation:  installation,
				DexConfig:     dexCfg,
				ClusterDomain: clusterName,
				TLSKeyPair:    tlsKeyPair,
				TrustedBundle: trustedCaBundle,
			}
		})

		It("should render all resources for a OIDC setup", func() {

			component := render.Dex(cfg)
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{render.DexPolicyName, render.DexNamespace, "projectcalico.org", "v3", "NetworkPolicy"},
				{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.DexNamespace, "projectcalico.org", "v3", "NetworkPolicy"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "ServiceAccount"},
				{render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Service"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRole"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRoleBinding"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "ConfigMap"},
				{render.DexObjectName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.OIDCSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Secret"},
				{render.OIDCSecretName, render.DexNamespace, "", "v1", "Secret"},
				{pullSecretName, render.DexNamespace, "", "v1", "Secret"},
			}

			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))

			d := rtest.GetResource(resources, "tigera-dex", "tigera-dex", "apps", "v1", "Deployment").(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))

			for k, v := range cfg.TrustedBundle.HashAnnotations() {
				Expect(d.Spec.Template.Annotations).To(HaveKeyWithValue(k, v))
			}
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(BeEquivalentTo(expectedVolumeMounts))
			Expect(d.Spec.Template.Spec.Volumes).To(BeEquivalentTo(expectedVolumes))
		})

		DescribeTable("should render the cluster name properly in the validator", func(clusterDomain string) {
			validatorConfig := render.NewDexKeyValidatorConfig(authentication, idpSecret, clusterDomain)
			validatorEnv := validatorConfig.RequiredEnv("")

			expectedUrl := fmt.Sprintf("https://tigera-dex.tigera-dex.svc.%s:5556", clusterDomain)
			Expect(validatorEnv[1].Value).To(Equal(expectedUrl + "/"))
			Expect(validatorEnv[4].Value).To(Equal(expectedUrl + "/dex/keys"))
		},
			Entry("default cluster domain", dns.DefaultClusterDomain),
			Entry("custom cluster domain", "custom.internal"),
		)

		It("should apply tolerations", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}
			cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{t}

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
		})

		It("should render all resources for a certificate management", func() {
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{}
			cfg.DexConfig = render.NewDexConfig(cfg.Installation.CertificateManagement, authentication, dexSecret, idpSecret, clusterName)

			component := render.Dex(cfg)
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{render.DexPolicyName, render.DexNamespace, "projectcalico.org", "v3", "NetworkPolicy"},
				{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.DexNamespace, "projectcalico.org", "v3", "NetworkPolicy"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "ServiceAccount"},
				{render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Service"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRole"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRoleBinding"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "ConfigMap"},
				{render.DexObjectName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.OIDCSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Secret"},
				{render.OIDCSecretName, render.DexNamespace, "", "v1", "Secret"},
				{pullSecretName, render.DexNamespace, "", "v1", "Secret"},
				{"tigera-dex:csr-creator", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			}

			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))
		})

		It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
			var replicas int32 = 1
			cfg.Installation.ControlPlaneReplicas = &replicas

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			var replicas int32 = 2
			cfg.Installation.ControlPlaneReplicas = &replicas

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
			Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-dex", "tigera-dex")))
		})

		Context("allow-tigera rendering", func() {
			policyName := types.NamespacedName{Name: "allow-tigera.allow-tigera-dex", Namespace: "tigera-dex"}

			getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
				if scenario.ManagedCluster {
					return nil
				}

				return testutils.SelectPolicyByProvider(scenario, expectedDexPolicy, expectedDexOpenshiftPolicy)
			}

			DescribeTable("should render allow-tigera policy",
				func(scenario testutils.AllowTigeraScenario) {
					cfg.Openshift = scenario.Openshift
					component := render.Dex(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				// Dex only renders in the presence of an Authentication CR, therefore does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
				Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			)
		})

	})
})
