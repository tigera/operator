// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package certificatemanagement

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ErrInvalidCertNoPEMData = errors.New("cert has no PEM data")

type KeyPair struct {
	CSRImage  string
	Name      string
	Namespace string
	// Golang's x509 package uses the 'any' type for all private and public keys. See x509.CreateCertificate() for more.
	PrivateKey     any
	PrivateKeyPEM  []byte
	CertificatePEM []byte
	ClusterDomain  string
	*operatorv1.CertificateManagement
	DNSNames []string
	Issuer   KeyPairInterface

	// OriginalSecret maintains a copy of the secret that the KeyPair was created from.
	OriginalSecret *corev1.Secret
}

func (k *KeyPair) GetCertificatePEM() []byte {
	return k.CertificatePEM
}

func (k *KeyPair) GetName() string {
	return k.Name
}

func (k *KeyPair) GetNamespace() string {
	return k.Namespace
}

// UseCertificateManagement is true if this secret is not BYO and certificate management is used to provide the a pair to a pod.
func (k *KeyPair) UseCertificateManagement() bool {
	return k.CertificateManagement != nil
}

// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
func (k *KeyPair) BYO() bool {
	return !k.UseCertificateManagement() && k.Issuer == nil
}

func (k *KeyPair) Secret(namespace string) *corev1.Secret {
	var data map[string][]byte
	if k.OriginalSecret == nil {
		data = make(map[string][]byte)
	} else {
		// Preserve original fields, such as uri-san, common-name or legacy names for tls.key and tls.crt.
		// This is necessary for example to support rolling calico-node updates of larger clusters from older versions.
		data = k.OriginalSecret.Data
	}
	data[corev1.TLSPrivateKeyKey] = k.PrivateKeyPEM
	data[corev1.TLSCertKey] = k.CertificatePEM
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: k.GetName(), Namespace: namespace},
		Data:       data,
	}
}

func (k *KeyPair) HashAnnotationKey() string {
	if k.GetNamespace() == "" {
		return fmt.Sprintf("hash.operator.tigera.io/%s", k.GetName())
	}
	return fmt.Sprintf("%s.hash.operator.tigera.io/%s", k.GetNamespace(), k.GetName())
}

func (k *KeyPair) HashAnnotationValue() string {
	if k.CertificateManagement != nil {
		return ""
	}
	return rmeta.AnnotationHash(rmeta.AnnotationHash(k.CertificatePEM))
}

func (k *KeyPair) Volume() corev1.Volume {
	volumeSource := CertificateVolumeSource(k.CertificateManagement, k.GetName())
	return corev1.Volume{
		Name:         k.GetName(),
		VolumeSource: volumeSource,
	}
}

func (k *KeyPair) VolumeMountCertificateFilePath() string {
	return fmt.Sprintf("/%s/%s", k.GetName(), corev1.TLSCertKey)
}

func (k *KeyPair) VolumeMountKeyFilePath() string {
	return fmt.Sprintf("/%s/%s", k.GetName(), corev1.TLSPrivateKeyKey)
}

func (k *KeyPair) VolumeMount(osType rmeta.OSType) corev1.VolumeMount {
	var mountPath string
	if osType == rmeta.OSTypeWindows {
		mountPath = fmt.Sprintf("c:/%s", k.GetName())
	} else {
		mountPath = fmt.Sprintf("/%s", k.GetName())
	}
	return corev1.VolumeMount{
		Name:      k.GetName(),
		MountPath: mountPath,
		ReadOnly:  true,
	}
}

// InitContainer contains an init container for making a CSR. is only applicable when certificate management is enabled.
func (k *KeyPair) InitContainer(namespace string) corev1.Container {
	initContainer := CreateCSRInitContainer(
		k.CertificateManagement,
		k.Name,
		k.CSRImage,
		k.GetName(),
		k.DNSNames[0],
		corev1.TLSPrivateKeyKey,
		corev1.TLSCertKey,
		k.DNSNames,
		namespace)
	initContainer.Name = fmt.Sprintf("%s-%s", k.GetName(), initContainer.Name)
	return initContainer
}

func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return nil, ErrInvalidCertNoPEMData
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (k *KeyPair) GetIssuer() CertificateInterface {
	return k.Issuer
}

func GetKeyCertPEM(secret *corev1.Secret) ([]byte, []byte) {
	const (
		legacySecretCertName  = "cert" // Formerly known as certificatemanagement.ManagerSecretCertName
		legacySecretKeyName   = "key"  // Formerly known as certificatemanagement.ManagerSecretKeyName
		legacySecretKeyName2  = "apiserver.key"
		legacySecretCertName2 = "apiserver.crt"
		legacySecretKeyName3  = "key.key"             // Formerly used for Felix and Typha.
		legacySecretCertName3 = "cert.crt"            // Formerly used for Felix and Typha.
		legacySecretKeyName4  = "managed-cluster.key" // Used for tunnel secrets
		legacySecretCertName4 = "managed-cluster.crt"
		legacySecretKeyName5  = "management-cluster.key"
		legacySecretCertName5 = "management-cluster.crt"
	)
	data := secret.Data
	for keyField, certField := range map[string]string{
		corev1.TLSPrivateKeyKey: corev1.TLSCertKey,
		legacySecretKeyName:     legacySecretCertName,
		legacySecretKeyName2:    legacySecretCertName2,
		legacySecretKeyName3:    legacySecretCertName3,
		legacySecretKeyName4:    legacySecretCertName4,
		legacySecretKeyName5:    legacySecretCertName5,
	} {
		key, cert := data[keyField], data[certField]
		if len(cert) > 0 {
			return key, cert
		}
	}
	return nil, nil
}

// NewKeyPair returns a KeyPair, which wraps a Secret object that contains a private key and a certificate. Whether certificate
// management is configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
func NewKeyPair(secret *corev1.Secret, dnsNames []string, clusterDomain string) KeyPairInterface {
	key, cert := GetKeyCertPEM(secret)
	return &KeyPair{
		Name:           secret.Name,
		PrivateKeyPEM:  key,
		CertificatePEM: cert,
		DNSNames:       dnsNames,
		ClusterDomain:  clusterDomain,
	}
}
