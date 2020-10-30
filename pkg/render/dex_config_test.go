package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("dex config tests", func() {
	t := true
	dexCfg := render.NewDexConfig(&operatorv1.Authentication{
		Spec: operatorv1.AuthenticationSpec{
			ManagerDomain: "https://example.com",
			OIDC: &operatorv1.AuthenticationOIDC{
				IssuerURL:                 "https://example.com",
				UsernameClaim:             "email",
				GroupsClaim:               "group",
				RequestedScopes:           []string{"scope"},
				InsecureSkipEmailVerified: &t,
			},
		},
	}, nil, nil, &corev1.Secret{
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
		}})

	Context("OIDC connector config options", func() {
		It("should configure insecureSkipEmailVerified ", func() {
			connector := dexCfg.Connector()
			cfg := connector["config"].(map[string]interface{})
			Expect(cfg["insecureSkipEmailVerified"]).To(Equal(true))
		})
	})
})
