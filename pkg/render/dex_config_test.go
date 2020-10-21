package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("DexConfig creation test", func() {
	const (
		issOidc          = "https://example.com"
		issGoogle        = "https://accounts.google.com"
		groupsClaim      = "mygroup"
		usernameClaim    = "myuser"
		userPrefix       = "u:"
		userPrefixOIDC   = "ou:"
		groupsPrefix     = "g:"
		groupsPrefixOIDC = "og:"
		domain           = "example.org"
	)
	dexTLS := render.CreateDexTLSSecret()
	dexSecret := render.CreateDexClientSecret()
	idpSecretOIDC := &corev1.Secret{Data: map[string][]byte{
		render.ClientSecretSecretField: []byte("secret"),
	}}

	var authenticationOIDC *v1.Authentication
	var authenticationGoogle *v1.Authentication
	BeforeEach(func() {
		authenticationOIDC = &v1.Authentication{
			Spec: v1.AuthenticationSpec{
				ManagerDomain:  domain,
				UsernamePrefix: userPrefix,
				GroupsPrefix:   groupsPrefix,
				OIDC: &v1.AuthenticationOIDC{
					IssuerURL:      issOidc,
					GroupsClaim:    groupsClaim,
					UsernameClaim:  usernameClaim,
					UsernamePrefix: userPrefixOIDC,
					GroupsPrefix:   groupsPrefixOIDC,
				},
			},
		}

		authenticationGoogle = &v1.Authentication{
			Spec: v1.AuthenticationSpec{
				ManagerDomain:  domain,
				UsernamePrefix: userPrefix,
				GroupsPrefix:   groupsPrefix,
				OIDC: &v1.AuthenticationOIDC{
					IssuerURL: issGoogle,
				},
			},
		}
	})

	Context("testing NewConfig() method options", func() {
		It("should create dex if all configs are passed", func() {
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{
				render.WithTLSSecret(dexTLS, false),
				render.WithDexSecret(dexSecret, false),
				render.WithIdpSecret(idpSecretOIDC),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(dex).NotTo(BeNil())
			Expect(dex.TLSSecret()).To(Equal(dexTLS))
			Expect(dex.IdpSecret()).To(Equal(idpSecretOIDC))
			Expect(dex.DexSecret()).To(Equal(dexSecret))
		})

		It("should create TLS secret if you tell it to", func() {
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{
				render.WithTLSSecret(nil, true),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(dex).NotTo(BeNil())
			Expect(dex.TLSSecret()).NotTo(BeNil())
			Expect(dex.TLSSecret().Data).To(Not(BeEmpty()))
		})

		It("should fail on missing TLS secret", func() {
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{
				render.WithTLSSecret(nil, false),
			})
			Expect(err).To(HaveOccurred())
			Expect(dex).To(BeNil())
		})

		It("should create dex secret if you tell it to", func() {
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{
				render.WithDexSecret(nil, true),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(dex).NotTo(BeNil())
			Expect(dex.DexSecret()).NotTo(BeNil())
			Expect(dex.DexSecret().Data).To(Not(BeEmpty()))
		})

		It("should fail on missing dex secret", func() {
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{
				render.WithDexSecret(nil, false),
			})
			Expect(err).To(HaveOccurred())
			Expect(dex).To(BeNil())
		})

		It("should fail on missing idp secret", func() {
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{
				render.WithIdpSecret(nil),
			})
			Expect(err).To(HaveOccurred())
			Expect(dex).To(BeNil())
		})

	})

	Context("should create oidc config", func() {
		It("should create dex without trouble if all possible configs are passed", func() {
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dex.IssuerURL()).To(Equal(issOidc))
			Expect(dex.UsernameClaim()).To(Equal(usernameClaim))
			Expect(dex.GroupsClaim()).To(Equal(groupsClaim))
			Expect(dex.UsernamePrefix()).To(Equal(userPrefix))
			Expect(dex.GroupsPrefix()).To(Equal(groupsPrefix))
			Expect(dex.ConnectorType()).To(Equal("oidc"))
			Expect(dex.BaseURL()).To(Equal("https://" + domain))
		})

		It("should backfill deprecated fields", func() {
			// Empty spec prefixes, but filled prefixes in the deprecated field.
			authenticationOIDC.Spec.UsernamePrefix = ""
			authenticationOIDC.Spec.GroupsPrefix = ""
			dex, err := render.NewDexConfig(authenticationOIDC, []render.DexOption{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dex.UsernamePrefix()).To(Equal(userPrefixOIDC))
			Expect(dex.GroupsPrefix()).To(Equal(groupsPrefixOIDC))
		})
	})

	Context("should create google/oidc config", func() {
		It("should create dex without trouble if all possible configs are passed", func() {
			dex, err := render.NewDexConfig(authenticationGoogle, []render.DexOption{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dex.IssuerURL()).To(BeEmpty())
			Expect(dex.UsernameClaim()).To(Equal("email"))
			Expect(dex.GroupsClaim()).To(Equal("groups"))
			Expect(dex.UsernamePrefix()).To(Equal(userPrefix))
			Expect(dex.GroupsPrefix()).To(Equal(groupsPrefix))
			Expect(dex.ConnectorType()).To(Equal("google"))
			Expect(dex.BaseURL()).To(Equal("https://" + domain))
		})
	})
})
