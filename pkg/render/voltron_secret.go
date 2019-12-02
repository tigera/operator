package render

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
)

// Voltron related constants.
const (
	VoltronDnsName      = "voltron"
	VoltronKeySizeBits  = 2048
	blockTypePrivateKey = "RSA PRIVATE KEY"
	blockTypeCert       = "CERTIFICATE"
)

// Secrets to establish a tunnel between Voltron and Guardian
// Differs from other secrets in the way that it needs a DNS name and KeyUsage.
func CreateSelfSignedVoltronSecret() (string, string) {
	template := template()
	privateKey, err := rsa.GenerateKey(rand.Reader, VoltronKeySizeBits)
	if err != nil {
		panic(err)
	}
	// Passing in template as parent, creates a self-signed cert.
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}
	// This will create a pem string for the privateKey and the cert
	var keyPem bytes.Buffer
	err = pem.Encode(&keyPem, &pem.Block{
		Type:  blockTypePrivateKey,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		panic(err)
	}
	var certPem bytes.Buffer
	if err := pem.Encode(&certPem, &pem.Block{Type: blockTypeCert, Bytes: cert}); err != nil {
		panic(err)
	}
	return keyPem.String(), certPem.String()
}

func template() *x509.Certificate {
	return &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{VoltronDnsName},
		Subject:               pkix.Name{CommonName: "tigera-voltron"},
		NotBefore:             time.Now(),
		// For now use the same lifetime as the other certs we generate. This will change when we implement rotation.
		NotAfter: time.Now().AddDate(0, 0, crypto.DefaultCACertificateLifetimeInDays),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
	}
}
