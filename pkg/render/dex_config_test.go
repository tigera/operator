// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("dex config tests", func() {
	verify := operatorv1.EmailVerificationTypeSkip
	email := "a@b.com"

	// Create two different authentication objects
	authentication := &operatorv1.Authentication{
		Spec: operatorv1.AuthenticationSpec{
			ManagerDomain: "https://example.com",
			OIDC: &operatorv1.AuthenticationOIDC{
				IssuerURL:         "https://example.com",
				UsernameClaim:     "email",
				GroupsClaim:       "group",
				RequestedScopes:   []string{"scope"},
				EmailVerification: &verify,
			},
		},
	}
	authenticationDiff := &operatorv1.Authentication{
		Spec: operatorv1.AuthenticationSpec{
			ManagerDomain: "https://example.org",
			OIDC: &operatorv1.AuthenticationOIDC{
				IssuerURL:     "https://example.org",
				UsernameClaim: "email",
			},
		},
	}
	// Create the necessary secrets.
	idpSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.OIDCSecretName,
			Namespace: render.OperatorNamespace(),
		},
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		Data: map[string][]byte{
			"adminEmail":           []byte(email),
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		},
	}
	dexSecret := render.CreateDexClientSecret()
	tlsSecret := render.CreateDexTLSSecret("tigera-dex.tigera-dex.svc.cluster.local")

	Context("OIDC connector config options", func() {
		It("should configure insecureSkipEmailVerified ", func() {
			connector := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).Connector()
			cfg := connector["config"].(map[string]interface{})
			Expect(cfg["insecureSkipEmailVerified"]).To(Equal(true))
		})
		It("should configure groups ", func() {
			connector := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).Connector()
			cfg := connector["config"].(map[string]interface{})
			Expect(cfg["insecureEnableGroups"]).To(Equal(true))
			Expect(cfg["claimMapping"].(map[string]string)["groups"]).To(Equal("group"))
		})
	})

	Context("Hashes should be consistent and not be affected by fields with pointers", func() {
		It("should produce consistent hashes for dex config", func() {
			hashes1 := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := render.NewDexConfig(authentication.DeepCopy(), tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := render.NewDexConfig(authenticationDiff, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(4))
			Expect(hashes2).To(HaveLen(4))
			Expect(hashes3).To(HaveLen(4))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for rp's", func() {
			hashes1 := render.NewDexRelyingPartyConfig(authentication, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := render.NewDexRelyingPartyConfig(authentication.DeepCopy(), tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := render.NewDexRelyingPartyConfig(authenticationDiff, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(3))
			Expect(hashes2).To(HaveLen(3))
			Expect(hashes3).To(HaveLen(3))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for verifiers", func() {
			hashes1 := render.NewDexKeyValidatorConfig(authentication, tlsSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := render.NewDexKeyValidatorConfig(authentication.DeepCopy(), tlsSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := render.NewDexKeyValidatorConfig(authenticationDiff, tlsSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(2))
			Expect(hashes2).To(HaveLen(2))
			Expect(hashes3).To(HaveLen(2))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})
	})
	google := &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{ManagerDomain: "https://127.0.0.1:9443", OIDC: &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"}}}
	DescribeTable("Test dex connector for Google ", func(secretData map[string][]byte, expectPresent bool) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.OIDCSecretName,
				Namespace: render.OperatorNamespace(),
			},
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			Data:     secretData,
		}
		dexConfig := render.NewDexConfig(google, tlsSecret, dexSecret, secret, dns.DefaultClusterDomain)
		connector := dexConfig.Connector()["config"].(map[string]interface{})

		email, emailFound := connector["adminEmail"]
		saPath, saFound := connector["serviceAccountFilePath"]
		if expectPresent {
			Expect(email).To(Equal(email))
			Expect(emailFound).To(BeTrue())
			Expect(saPath).To(Equal("/etc/dex/secrets/google-groups.json"))
			Expect(saFound).To(BeTrue())
		} else {
			Expect(emailFound).To(BeFalse())
			Expect(saFound).To(BeFalse())
		}
	},
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"adminEmail":           []byte(email),
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		}, true),
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"clientID":     []byte("a.b.com"),
			"clientSecret": []byte("my-secret"),
		}, false),
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		}, false),
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"adminEmail":   []byte(email),
			"clientID":     []byte("a.b.com"),
			"clientSecret": []byte("my-secret"),
		}, false))
})
