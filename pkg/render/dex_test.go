package render_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("dex rendering tests", func() {
	const clusterName = "svc.cluster.local"
	Context("dex is configured for oidc", func() {

		const (
			rbac           = "rbac.authorization.k8s.io"
			pullSecretName = "tigera-pull-secret"
		)

		var (
			installation   *operatorv1.InstallationSpec
			authentication *operatorv1.Authentication
			tlsSecret      *corev1.Secret
			certSecret     *corev1.Secret
			dexSecret      *corev1.Secret
			idpSecret      *corev1.Secret
			pullSecrets    []*corev1.Secret
			replicas       int32
		)

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
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

			tlsSecret = render.CreateDexTLSSecret("tigera-dex.tigera-dex.svc.cluster.local")
			certSecret = render.CreateCertificateSecret(tlsSecret.Data[corev1.TLSCertKey], render.DexCertSecretName, common.OperatorNamespace())
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
		})

		It("should render all resources for a OIDC setup", func() {

			dexCfg := render.NewDexConfig(installation.CertificateManagement, authentication, tlsSecret, dexSecret, idpSecret, clusterName)

			component := render.Dex(pullSecrets, false, installation, dexCfg, clusterName, false)
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{render.DexObjectName, render.DexNamespace, "", "v1", "ServiceAccount"},
				{render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Service"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRole"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRoleBinding"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "ConfigMap"},
				{render.DexTLSSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexObjectName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.OIDCSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexCertSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexTLSSecretName, render.DexNamespace, "", "v1", "Secret"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Secret"},
				{render.OIDCSecretName, render.DexNamespace, "", "v1", "Secret"},
				{pullSecretName, render.DexNamespace, "", "v1", "Secret"},
			}

			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))
		})

		DescribeTable("should render the cluster name properly in the validator and rp configs", func(clusterDomain string) {
			validatorConfig := render.NewDexKeyValidatorConfig(authentication, idpSecret, certSecret, clusterDomain)
			validatorEnv := validatorConfig.RequiredEnv("")

			expectedUrl := fmt.Sprintf("https://tigera-dex.tigera-dex.svc.%s:5556", clusterDomain)
			Expect(validatorEnv[1].Value).To(Equal(expectedUrl + "/"))
			Expect(validatorEnv[4].Value).To(Equal(expectedUrl + "/dex/keys"))

			rpConfig := render.NewDexRelyingPartyConfig(authentication, certSecret, dexSecret, clusterDomain)
			Expect(rpConfig.UserInfoURI()).To(Equal(expectedUrl + "/dex/userinfo"))
			Expect(rpConfig.TokenURI()).To(Equal(expectedUrl + "/dex/token"))
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

			dexCfg := render.NewDexConfig(installation.CertificateManagement, authentication, tlsSecret, dexSecret, idpSecret, clusterName)
			component := render.Dex(pullSecrets, false, &operatorv1.InstallationSpec{
				ControlPlaneReplicas:    installation.ControlPlaneReplicas,
				ControlPlaneTolerations: []corev1.Toleration{t},
			}, dexCfg, clusterName, false)
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster))
		})

		It("should render all resources for a certificate management", func() {
			installation.CertificateManagement = &operatorv1.CertificateManagement{}
			dexCfg := render.NewDexConfig(installation.CertificateManagement, authentication, tlsSecret, dexSecret, idpSecret, clusterName)

			component := render.Dex(pullSecrets, false, installation, dexCfg, clusterName, false)
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{render.DexObjectName, render.DexNamespace, "", "v1", "ServiceAccount"},
				{render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Service"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRole"},
				{render.DexObjectName, "", rbac, "v1", "ClusterRoleBinding"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "ConfigMap"},
				{render.DexTLSSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexObjectName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.OIDCSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexCertSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexTLSSecretName, render.DexNamespace, "", "v1", "Secret"},
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
			installation.ControlPlaneReplicas = &replicas

			dexCfg := render.NewDexConfig(installation.CertificateManagement, authentication, tlsSecret, dexSecret, idpSecret, clusterName)
			component := render.Dex(pullSecrets, false, installation, dexCfg, clusterName, false)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			var replicas int32 = 2
			installation.ControlPlaneReplicas = &replicas

			dexCfg := render.NewDexConfig(installation.CertificateManagement, authentication, tlsSecret, dexSecret, idpSecret, clusterName)
			component := render.Dex(pullSecrets, false, installation, dexCfg, clusterName, false)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
			Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-dex", "tigera-dex")))
		})
	})
})
