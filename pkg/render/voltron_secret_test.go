package render_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/openshift/library-go/pkg/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Voltron cert generation tests", func() {

	var newCert *x509.Certificate

	It("should create a valid cert and key", func() {
		key, cert := render.CreateSelfSignedVoltronSecret()

		_, err := tls.X509KeyPair([]byte(cert), []byte(key))
		Expect(err).ShouldNot(HaveOccurred())

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(cert))
		Expect(ok).To(BeTrue())

		block, _ := pem.Decode([]byte(cert))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(block).To(Not(BeNil()))

		newCert, err = x509.ParseCertificate(block.Bytes)
		Expect(err).ShouldNot(HaveOccurred())

		opts := x509.VerifyOptions{
			DNSName: render.VoltronDnsName,
			Roots:   roots,
		}

		_, err = newCert.Verify(opts)
		Expect(err).ShouldNot(HaveOccurred())

	})

	It("should expire after a year", func() {
		opts := x509.VerifyOptions{
			DNSName:     render.VoltronDnsName,
			Roots:       x509.NewCertPool(),
			CurrentTime: time.Now().AddDate(0, 0, crypto.DefaultCACertificateLifetimeInDays+1),
		}
		_, err := newCert.Verify(opts)
		Expect(err).Should(HaveOccurred())

	})
})
