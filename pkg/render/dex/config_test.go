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

package dex_test

import (
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"

	rcommon "github.com/tigera/operator/pkg/render/common"
	"github.com/tigera/operator/pkg/render/dex"

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
			Name:      dex.OIDCSecretName,
			Namespace: rcommon.OperatorNamespace(),
		},
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		Data: map[string][]byte{
			"adminEmail":           []byte("a@b.com"),
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		},
	}
	dexSecret := dex.CreateClientSecret()
	tlsSecret := dex.CreateTLSSecret("tigera-dex.tigera-dex.svc.cluster.local")

	Context("OIDC connector config options", func() {
		It("should configure insecureSkipEmailVerified ", func() {
			connector := dex.NewConfig(authentication, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).Connector()
			cfg := connector["config"].(map[string]interface{})
			Expect(cfg["insecureSkipEmailVerified"]).To(Equal(true))
		})
	})

	Context("Hashes should be consistent and not be affected by fields with pointers", func() {
		It("should produce consistent hashes for dex config", func() {
			hashes1 := dex.NewConfig(authentication, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := dex.NewConfig(authentication.DeepCopy(), tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := dex.NewConfig(authenticationDiff, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(4))
			Expect(hashes2).To(HaveLen(4))
			Expect(hashes3).To(HaveLen(4))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for rp's", func() {
			hashes1 := dex.NewRelyingPartyConfig(authentication, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := dex.NewRelyingPartyConfig(authentication.DeepCopy(), tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := dex.NewRelyingPartyConfig(authenticationDiff, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(3))
			Expect(hashes2).To(HaveLen(3))
			Expect(hashes3).To(HaveLen(3))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for verifiers", func() {
			hashes1 := dex.NewKeyValidatorConfig(authentication, tlsSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := dex.NewKeyValidatorConfig(authentication.DeepCopy(), tlsSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := dex.NewKeyValidatorConfig(authenticationDiff, tlsSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(2))
			Expect(hashes2).To(HaveLen(2))
			Expect(hashes3).To(HaveLen(2))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})
	})
})
