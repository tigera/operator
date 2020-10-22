package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
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

	Context("should create oidc config", func() {
		It("all dex config methods work as expected", func() {
			dex := render.NewDexConfig(authenticationOIDC, nil, nil, nil)
			Expect(dex.IssuerURL()).To(Equal(issOidc))
			Expect(dex.UsernameClaim()).To(Equal(usernameClaim))
			Expect(dex.GroupsClaim()).To(Equal(groupsClaim))
			Expect(dex.UsernamePrefix()).To(Equal(userPrefix))
			Expect(dex.GroupsPrefix()).To(Equal(groupsPrefix))
			Expect(dex.ConnectorType()).To(Equal("oidc"))
			Expect(dex.ManagerURI()).To(Equal("https://" + domain))
		})

	})

	Context("should create google/oidc config", func() {
		It("should create dex without trouble if all possible configs are passed", func() {
			dex := render.NewDexConfig(authenticationGoogle, nil, nil, nil)
			Expect(dex.IssuerURL()).To(BeEmpty())
			Expect(dex.UsernameClaim()).To(Equal("email"))
			Expect(dex.GroupsClaim()).To(Equal("groups"))
			Expect(dex.UsernamePrefix()).To(Equal(userPrefix))
			Expect(dex.GroupsPrefix()).To(Equal(groupsPrefix))
			Expect(dex.ConnectorType()).To(Equal("google"))
			Expect(dex.ManagerURI()).To(Equal("https://" + domain))
		})
	})
})
