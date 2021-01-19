package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("dex rendering tests", func() {
	Context("dex is configured for oidc", func() {
		It("should render all resources for a OIDC setup", func() {

			const (
				rbac           = "rbac.authorization.k8s.io"
				pullSecretName = "tigera-pull-secret"
			)

			installation := &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}

			tlsSecret := render.CreateDexTLSSecret()
			dexSecret := render.CreateDexClientSecret()
			idpSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.OIDCSecretName,
					Namespace: render.OperatorNamespace(),
				},
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				Data: map[string][]byte{
					"adminEmail":           []byte("a@b.com"),
					"clientID":             []byte("a.b.com"),
					"clientSecret":         []byte("my-secret"),
					"serviceAccountSecret": []byte("my-secret2"),
				}}
			pullSecrets := []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pullSecretName,
						Namespace: render.OperatorNamespace(),
					},
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				}}
			dexCfg := render.NewDexConfig(&operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:       "https://example.com",
						UsernameClaim:   "email",
						GroupsClaim:     "group",
						RequestedScopes: []string{"scope"},
					},
				},
			}, tlsSecret, dexSecret, idpSecret)

			component := render.Dex(pullSecrets, false, installation, dexCfg)
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
				{render.DexTLSSecretName, render.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexObjectName, render.OperatorNamespace(), "", "v1", "Secret"},
				{render.OIDCSecretName, render.OperatorNamespace(), "", "v1", "Secret"},
				{render.DexTLSSecretName, render.DexNamespace, "", "v1", "Secret"},
				{render.DexObjectName, render.DexNamespace, "", "v1", "Secret"},
				{render.OIDCSecretName, render.DexNamespace, "", "v1", "Secret"},
				{pullSecretName, render.DexNamespace, "", "v1", "Secret"},
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
		})
	})
})
