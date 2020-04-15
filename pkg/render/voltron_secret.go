// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package render

// Voltron related constants.
const (
	VoltronDnsName      = "voltron"
	VoltronKeySizeBits  = 2048
	blockTypePrivateKey = "RSA PRIVATE KEY"
	blockTypeCert       = "CERTIFICATE"
)

/*
// Secrets to establish a tunnel between Voltron and Guardian
// Differs from other secrets in the way that it needs a DNS name and KeyUsage.
func ceateSelfSignedVoltronSecret() (string, string) {
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
}*/
