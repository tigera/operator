package dex_test

import (
	"fmt"

	"github.com/tigera/operator/pkg/render/testutil"

	"github.com/tigera/operator/pkg/render/dex"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"
	rcommon "github.com/tigera/operator/pkg/render/common"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("dex rendering tests", func() {
	Context("dex is configured for oidc", func() {

		const (
			rbac           = "rbac.authorization.k8s.io"
			pullSecretName = "tigera-pull-secret"
		)

		var (
			installation   *operatorv1.InstallationSpec
			authentication *operatorv1.Authentication
			tlsSecret      *corev1.Secret
			dexSecret      *corev1.Secret
			idpSecret      *corev1.Secret
			pullSecrets    []*corev1.Secret
		)

		BeforeEach(func() {

			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
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

			tlsSecret = dex.CreateTLSSecret("tigera-dex.tigera-dex.svc.cluster.local")
			dexSecret = dex.CreateClientSecret()
			idpSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      dex.OIDCSecretName,
					Namespace: rcommon.OperatorNamespace(),
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
						Namespace: rcommon.OperatorNamespace(),
					},
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				}}
		})

		It("should render all resources for a OIDC setup", func() {

			dexCfg := dex.NewConfig(authentication, tlsSecret, dexSecret, idpSecret, "svc.cluster.local")

			component := dex.NewComponent(pullSecrets, false, installation, dexCfg)
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{dex.ObjectName, dex.Namespace, "", "v1", "ServiceAccount"},
				{dex.ObjectName, dex.Namespace, "apps", "v1", "Deployment"},
				{dex.ObjectName, dex.Namespace, "", "v1", "Service"},
				{dex.ObjectName, "", rbac, "v1", "ClusterRole"},
				{dex.ObjectName, "", rbac, "v1", "ClusterRoleBinding"},
				{dex.ObjectName, dex.Namespace, "", "v1", "ConfigMap"},
				{dex.TLSSecretName, rcommon.OperatorNamespace(), "", "v1", "Secret"},
				{dex.ObjectName, rcommon.OperatorNamespace(), "", "v1", "Secret"},
				{dex.OIDCSecretName, rcommon.OperatorNamespace(), "", "v1", "Secret"},
				{dex.TLSSecretName, dex.Namespace, "", "v1", "Secret"},
				{dex.ObjectName, dex.Namespace, "", "v1", "Secret"},
				{dex.OIDCSecretName, dex.Namespace, "", "v1", "Secret"},
				{pullSecretName, dex.Namespace, "", "v1", "Secret"},
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				testutil.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
		})

		DescribeTable("should render the cluster name properly in the validator and rp configs", func(clusterDomain string) {
			validatorConfig := dex.NewKeyValidatorConfig(authentication, tlsSecret, clusterDomain)
			validatorEnv := validatorConfig.RequiredEnv("")

			expectedUrl := fmt.Sprintf("https://tigera-dex.tigera-dex.svc.%s:5556", clusterDomain)
			Expect(validatorEnv[2].Value).To(Equal(expectedUrl + "/"))
			Expect(validatorEnv[3].Value).To(Equal(expectedUrl + "/dex/keys"))

			rpConfig := dex.NewRelyingPartyConfig(authentication, tlsSecret, dexSecret, clusterDomain)
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

			dexCfg := dex.NewConfig(authentication, tlsSecret, dexSecret, idpSecret, "svc.cluster.local")
			component := dex.NewComponent(pullSecrets, false, &operatorv1.InstallationSpec{
				ControlPlaneTolerations: []corev1.Toleration{t},
			}, dexCfg)
			resources, _ := component.Objects()
			d := testutil.GetResource(resources, dex.ObjectName, dex.Namespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(t, rcommon.TolerateMaster))
		})
	})
})
