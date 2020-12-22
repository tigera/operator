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

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand"
	"strings"
	"time"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/crypto"
)

// Voltron related constants.
const (
	VoltronDnsName      = "voltron"
	VoltronKeySizeBits  = 2048
	blockTypePrivateKey = "RSA PRIVATE KEY"
	blockTypeCert       = "CERTIFICATE"
)

// Creates a secret that will store the CA needed to generated certificates
// for managed cluster registration
func voltronTunnelSecret() *corev1.Secret {
	key, cert := createSelfSignedSecret("tigera-voltron", []string{VoltronDnsName})
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronTunnelSecretName,
			Namespace: OperatorNamespace(),
		},
		Data: map[string][]byte{
			VoltronTunnelSecretCertName: []byte(cert),
			VoltronTunnelSecretKeyName:  []byte(key),
		},
	}
}

func CreateDexTLSSecret(dexCommonName string) *corev1.Secret {
	key, cert := createSelfSignedSecret(dexCommonName, []string{dexCommonName})
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexTLSSecretName,
			Namespace: OperatorNamespace(),
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(cert),
			corev1.TLSPrivateKeyKey: []byte(key),
		},
	}
}

// Secrets to establish a tunnel between Voltron and Guardian
// Differs from other secrets in the way that it needs a DNS name and KeyUsage.
func createSelfSignedSecret(cn string, altNames []string) (string, string) {
	template := template(cn, altNames)
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

func template(cn string, altNames []string) *x509.Certificate {
	return &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1),
		DNSNames:              altNames,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		// For now use the same lifetime as the other certs we generate. This will change when we implement rotation.
		NotAfter: time.Now().AddDate(0, 0, crypto.DefaultCACertificateLifetimeInDays),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
	}
}

func generatePassword(length int) string {
	mrand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[mrand.Intn(len(chars))])
	}
	return b.String()
}

func CreateDexClientSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-dex",
			Namespace: OperatorNamespace(),
		},
		Data: map[string][]byte{
			ClientSecretSecretField: []byte(generatePassword(24)),
		},
	}
}

func CreateCSRInitContainer(
	installation *operator.InstallationSpec,
	cm *operator.CertificateManagement,
	mountName string,
	commonName string,
	keyName string,
	certName string,
	registerApiserver bool) corev1.Container {
	return corev1.Container{
		Name:            "key-cert-provisioner",
		Image:           components.GetReference(components.ComponentCSRInitContainer, "docker.io/", installation.ImagePath),
		ImagePullPolicy: "Always", //todo: delete this line.
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/secret", Name: mountName, ReadOnly: false},
		},
		Env: []corev1.EnvVar{
			{Name: "SECRET_LOCATION", Value: "/secret/"},
			{Name: "SIGNER", Value: cm.SignerName},
			{Name: "COMMON_NAME", Value: commonName},
			{Name: "KEY_ALGORITHM", Value: fmt.Sprintf("%v", installation.CertificateManagement.KeyAlgorithm)},
			{Name: "SIGNATURE_ALGORITHM", Value: fmt.Sprintf("%v", installation.CertificateManagement.SignatureAlgorithm)},
			{Name: "REGISTER_APISERVER", Value: fmt.Sprintf("%v", registerApiserver)},
			{Name: "KEY_NAME", Value: keyName},
			{Name: "CERT_NAME", Value: certName},
			{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "status.podIP",
				},
			}},
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			}},
			{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			}},
			{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.uid",
				},
			}},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: Bool(true),
		},
	}

}
