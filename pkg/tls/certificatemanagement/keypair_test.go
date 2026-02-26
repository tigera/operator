// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package certificatemanagement_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("TLS secret metadata", func() {
	Describe("KeyPair.Secret()", func() {
		It("should add labels and annotations to the secret from a valid cert", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("test-secret", "test-ns", "test-cn", []string{"foo.example.com", "bar.example.com"})
			Expect(err).NotTo(HaveOccurred())

			kp := certificatemanagement.NewKeyPair(secret, []string{"foo.example.com"}, "cluster.local")
			s := kp.Secret("test-ns")

			By("verifying labels are present")
			Expect(s.Labels).To(HaveKey("operator.tigera.io/signer"))

			By("verifying annotations are present")
			Expect(s.Annotations).To(HaveKey("operator.tigera.io/cert-issuer"))
			Expect(s.Annotations).To(HaveKey("operator.tigera.io/cert-signer"))
			Expect(s.Annotations).To(HaveKey("operator.tigera.io/cert-expiry"))
			Expect(s.Annotations).To(HaveKey("operator.tigera.io/cert-dns-names"))

			By("verifying the issuer matches the CN we used")
			Expect(s.Annotations["operator.tigera.io/cert-issuer"]).To(Equal("test-cn"))
			Expect(s.Annotations["operator.tigera.io/cert-signer"]).To(Equal("test-cn"))

			By("verifying the DNS names annotation contains our DNS names")
			dnsNames := s.Annotations["operator.tigera.io/cert-dns-names"]
			Expect(dnsNames).To(ContainSubstring("foo.example.com"))
			Expect(dnsNames).To(ContainSubstring("bar.example.com"))

			By("verifying cert-expiry is in RFC3339 format")
			Expect(s.Annotations["operator.tigera.io/cert-expiry"]).To(MatchRegexp(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`))
		})

		It("should omit cert-ip-sans when there are no IP SANs", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("test-secret", "test-ns", "test-cn", []string{"foo.example.com"})
			Expect(err).NotTo(HaveOccurred())

			kp := certificatemanagement.NewKeyPair(secret, []string{"foo.example.com"}, "cluster.local")
			s := kp.Secret("test-ns")

			Expect(s.Annotations).NotTo(HaveKey("operator.tigera.io/cert-ip-sans"))
		})

		It("should return empty labels/annotations when cert PEM is empty", func() {
			kp := &certificatemanagement.KeyPair{
				Name:           "empty-cert",
				PrivateKeyPEM:  []byte("fake-key"),
				CertificatePEM: []byte{},
			}
			s := kp.Secret("test-ns")

			Expect(s.Labels).To(BeEmpty())
			Expect(s.Annotations).To(BeEmpty())
		})
	})

	Describe("CreateSelfSignedSecret()", func() {
		It("should include labels and annotations on the created secret", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "my-issuer@1234567890", []string{"dns1.example.com"})
			Expect(err).NotTo(HaveOccurred())

			By("verifying labels")
			Expect(secret.Labels).To(HaveKeyWithValue("operator.tigera.io/signer", "my-issuer"))

			By("verifying annotations")
			Expect(secret.Annotations["operator.tigera.io/cert-issuer"]).To(Equal("my-issuer@1234567890"))
			Expect(secret.Annotations["operator.tigera.io/cert-signer"]).To(Equal("my-issuer@1234567890"))
			Expect(secret.Annotations).To(HaveKey("operator.tigera.io/cert-expiry"))
			Expect(secret.Annotations["operator.tigera.io/cert-dns-names"]).To(Equal("dns1.example.com"))
		})

		It("should handle the signer label with no @ in the CN", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "simple-signer", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(secret.Labels["operator.tigera.io/signer"]).To(Equal("simple-signer"))
		})

		It("should truncate the signer label to 63 characters", func() {
			longCN := strings.Repeat("a", 100)
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", longCN, nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(secret.Labels["operator.tigera.io/signer"])).To(Equal(63))
		})
	})
})
