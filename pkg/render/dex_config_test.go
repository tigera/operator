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
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("dex config tests", func() {
	verify := operatorv1.EmailVerificationTypeSkip

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
			ManagerDomain: "https://example.com",
			OIDC: &operatorv1.AuthenticationOIDC{
				IssuerURL:     "https://example.com",
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
			"adminEmail":           []byte("a@b.com"),
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		},
	}
	dexSecret := render.CreateDexClientSecret()
	tlsSecret := render.CreateDexTLSSecret("tigera-dex.tigera-dex.svc.cluster.local")

	Context("OIDC connector config options", func() {
		It("should configure insecureSkipEmailVerified ", func() {
			connector := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret).Connector()
			cfg := connector["config"].(map[string]interface{})
			Expect(cfg["insecureSkipEmailVerified"]).To(Equal(true))
		})
	})

	Context("Hashes should be consistent and not be affected by fields with pointers", func() {
		It("should produce consistent hashes for dex config", func() {
			hashes1 := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret).RequiredAnnotations()
			hashes2 := render.NewDexConfig(authentication.DeepCopy(), tlsSecret, dexSecret, idpSecret).RequiredAnnotations()
			hashes3 := render.NewDexConfig(authenticationDiff, tlsSecret, dexSecret, idpSecret).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(4))
			Expect(hashes2).To(HaveLen(4))
			Expect(hashes3).To(HaveLen(4))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for rp's", func() {
			hashes1 := render.NewDexRelyingPartyConfig(authentication, tlsSecret, idpSecret).RequiredAnnotations()
			hashes2 := render.NewDexRelyingPartyConfig(authentication.DeepCopy(), tlsSecret, idpSecret).RequiredAnnotations()
			hashes3 := render.NewDexRelyingPartyConfig(authenticationDiff, tlsSecret, idpSecret).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(3))
			Expect(hashes2).To(HaveLen(3))
			Expect(hashes3).To(HaveLen(3))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for verifiers", func() {
			hashes1 := render.NewDexKeyValidatorConfig(authentication, tlsSecret).RequiredAnnotations()
			hashes2 := render.NewDexKeyValidatorConfig(authentication.DeepCopy(), tlsSecret).RequiredAnnotations()
			hashes3 := render.NewDexKeyValidatorConfig(authenticationDiff, tlsSecret).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(2))
			Expect(hashes2).To(HaveLen(2))
			Expect(hashes3).To(HaveLen(2))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})
	})
})
