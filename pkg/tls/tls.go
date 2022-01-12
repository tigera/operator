// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

// tls package contains tls related helper functions related to generating and modifying certificates and private keys
// used for tls.
package tls

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"

	operatorv1 "github.com/tigera/operator/api/v1"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func SetClientAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	return nil
}
func SetServerAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	return nil
}

func MakeCA(signerName string) (*crypto.CA, error) {
	caConfig, err := crypto.MakeSelfSignedCAConfigForDuration(
		signerName,
		100*365*24*time.Hour, //100years*365days*24hours
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA: %s", err)
	}
	return &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          caConfig,
	}, nil
}

const (
	TigeraCASecretName          = "tigera-ca-private"
	TrustedCertConfigMapName    = "tigera-ca-bundle"
	TrustedCertConfigMapKeyName = "tigera-ca-bundle.crt"
	TrustedCertVolumeMountPath  = "/etc/pki/tls/certs/"
	TrustedCertBundleMountPath  = "/etc/pki/tls/certs/tigera-ca-bundle.crt"
)

// TigeraCA is a signer of new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, TigeraCA will preserve and return them.
type TigeraCA interface {
	// CertificateManagement returns the CertificateManagement object or nil if it is not configured.
	CertificateManagement() *operatorv1.CertificateManagement
	// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, a k8s.io NotFound error is returned.
	GetKeyPair(cli client.Client, secretName, secretNamespace string) (KeyPair, error)
	// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
	GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (KeyPair, error)
	// GetCertificate returns a Certificate. If the certificate is not found a k8s.io NotFound error is returned.
	GetCertificate(cli client.Client, secretName, secretNamespace string) (Certificate, error)
	// Issued returns true if the provided certificate was signed by TigeraCA and returns false for user provided KeyPairs or Certificate Management.
	Issued(certificate Certificate) bool
	KeyPair
}

// KeyPair wraps a Secret object that contains a private key and a certificate. Whether CertificateManagement is
// configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
type KeyPair interface {
	UseCertificateManagement() bool
	InitContainer(namespace, csrImage string) corev1.Container
	VolumeMount(folder string) corev1.VolumeMount
	Volume() corev1.Volume
	Certificate
}

// Certificate wraps the certificate. Combine this with a TrustedBundle, to mount a trusted certificate bundle to a pod.
type Certificate interface {
	X509Certificate() *x509.Certificate
	Secret(namespace string) *corev1.Secret
	HashAnnotationKey() string
	HashAnnotationValue() string
}

// TrustedBundle is used to create a trusted certificate bundle of the TigeraCA and 0 or more Certificates.
type TrustedBundle interface {
	MountPath() string
	ConfigMap(namespace string) *corev1.ConfigMap
	HashAnnotations() map[string]string
	VolumeMount() corev1.VolumeMount
	Volume() corev1.Volume
	//AddPEM adds a PEM block to the certificate bundle.
	AddPEM(annotationName string, pem []byte)
}
