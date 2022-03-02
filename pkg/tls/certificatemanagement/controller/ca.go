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

package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certificatemanagement/render"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	log                     = logf.Log.WithName("tls")
	errInvalidCertDNSNames  = errors.New("cert has the wrong DNS names")
	errInvalidCertNoPEMData = errors.New("cert has no PEM data")
)

type trustedBundle struct {
	certificateManager render.CertificateManager
	pem                []byte
	annotations        map[string]string
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
func CreateTrustedBundle(ca render.CertificateManager, certificates ...render.Certificate) render.TrustedBundle {
	bundle := &trustedBundle{certificateManager: ca,
		pem: []byte(fmt.Sprintf("# certificate name: %s\n%s\n\n", ca.Name(), string(ca.CertificatePEM()))),
		annotations: map[string]string{
			ca.HashAnnotationKey(): ca.HashAnnotationValue(),
		}}
	bundle.AddCertificates(certificates...)
	return bundle
}

// AddCertificates Adds the PEM blocks of the certificates to the bundle.
func (t *trustedBundle) AddCertificates(certificates ...render.Certificate) {
	pemBuf := bytes.Buffer{}
	pemBuf.Write(t.pem) // err is always nil.
	for _, cert := range certificates {
		if cert != nil && cert.CertificatePEM() != nil && !t.certificateManager.Issued(cert.CertificatePEM()) {
			t.annotations[fmt.Sprintf("hash.operator.tigera.io/%s", cert.Name())] = rmeta.AnnotationHash(cert.CertificatePEM())
			pemBuf.WriteString(fmt.Sprintf("# certificate name: %s\n%s\n\n",
				cert.Name(), string(cert.CertificatePEM()))) // err is always nil
		}
	}
	t.pem = pemBuf.Bytes()
}

func (t *trustedBundle) MountPath() string {
	return render.TrustedCertBundleMountPath
}

func (t *trustedBundle) HashAnnotations() map[string]string {
	return t.annotations
}

func (t *trustedBundle) VolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      render.TrustedCertConfigMapName,
		MountPath: render.TrustedCertVolumeMountPath,
		ReadOnly:  true,
	}
}

func (t *trustedBundle) Volume() corev1.Volume {
	return corev1.Volume{
		Name: render.TrustedCertConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: render.TrustedCertConfigMapName},
			},
		},
	}
}

func (t *trustedBundle) ConfigMap(namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.TrustedCertConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			render.TrustedCertConfigMapKeyName: string(t.pem),
		},
	}
}

// AddPEM Adds a PEM block to the bundle.
func (t *trustedBundle) AddPEM(annotationName string, pem []byte) {
	t.annotations[annotationName] = rmeta.AnnotationHash(pem)
	buf := bytes.Buffer{}
	buf.Write(t.pem)
	buf.WriteString("\n\n")
	buf.Write(pem)
	t.pem = buf.Bytes()
}

type certificateManager struct {
	*x509.Certificate
	*crypto.CA
	keyPair
}

// CreateCertificateManager creates a signer of new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
func CreateCertificateManager(cli client.Client, installation *operatorv1.InstallationSpec, clusterDomain string) (render.CertificateManager, error) {
	var (
		cryptoCA                      *crypto.CA
		csrImage                      string
		privateKeyPEM, certificatePEM []byte
	)
	var certificateManagement *operatorv1.CertificateManagement
	if installation != nil && installation.CertificateManagement != nil {
		certificateManagement = installation.CertificateManagement
		imageSet, err := imageset.GetImageSet(context.Background(), cli, installation.Variant)
		if err != nil {
			return nil, err
		}
		csrImage, err = components.GetReference(
			components.ComponentCSRInitContainer,
			installation.Registry,
			installation.ImagePath,
			installation.ImagePrefix,
			imageSet,
		)
		if err != nil {
			return nil, err
		}
		certificatePEM = certificateManagement.CACert
	} else {
		caSecret := &corev1.Secret{}
		err := cli.Get(context.Background(), types.NamespacedName{
			Name:      render.CASecretName,
			Namespace: common.OperatorNamespace(),
		}, caSecret)
		if err != nil && !kerrors.IsNotFound(err) {
			return nil, err
		}
		if caSecret == nil ||
			len(caSecret.Data) == 0 ||
			len(caSecret.Data[corev1.TLSPrivateKeyKey]) == 0 ||
			len(caSecret.Data[corev1.TLSCertKey]) == 0 {
			cryptoCA, err = tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix)
			if err != nil {
				return nil, err
			}
			keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
			if err := cryptoCA.Config.WriteCertConfig(crtContent, keyContent); err != nil {
				return nil, err
			}
			privateKeyPEM, certificatePEM = keyContent.Bytes(), crtContent.Bytes()
		} else {
			privateKeyPEM, certificatePEM = caSecret.Data[corev1.TLSPrivateKeyKey], caSecret.Data[corev1.TLSCertKey]
			cryptoCA, err = crypto.GetCAFromBytes(certificatePEM, privateKeyPEM)
		}
	}
	x509Cert, err := parseCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	return &certificateManager{
		CA:          cryptoCA,
		Certificate: x509Cert,
		keyPair: keyPair{
			name:                  render.CASecretName,
			privateKeyPem:         privateKeyPEM,
			certificatePEM:        certificatePEM,
			csrImage:              csrImage,
			clusterDomain:         clusterDomain,
			CertificateManagement: certificateManagement,
		},
	}, nil
}

// AddToStatusManager lets the status manager monitor pending CSRs if the certificate management is enabled.
func (cm *certificateManager) AddToStatusManager(statusManager status.StatusManager, namespace string) {
	if cm.CertificateManagement() != nil {
		statusManager.AddCertificateSigningRequests(namespace, map[string]string{"k8s-app": namespace})
	} else {
		statusManager.RemoveCertificateSigningRequests(namespace)
	}
}

// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
func (cm *certificateManager) GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (render.KeyPair, error) {
	secret := &corev1.Secret{}
	kp := &keyPair{
		name:     secretName,
		ca:       cm,
		dnsNames: dnsNames,
	}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	createNew := false
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, err
		}
		createNew = true
	} else {
		kp.privateKeyPem, kp.certificatePEM = getKeyCertPEM(secret)
		if len(kp.privateKeyPem) == 0 || len(kp.certificatePEM) == 0 {
			return nil, fmt.Errorf("secret %s/%s is missing a certificate", secret.Namespace, secret.Name)
		}
		cert, err := parseCertificate(kp.certificatePEM)
		if err != nil {
			return nil, err
		}
		err = hasExpectedDNSNames(cert, dnsNames)
		if err == errInvalidCertDNSNames {
			if strings.HasPrefix(cert.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) && !cm.Issued(kp.certificatePEM) {
				createNew = true
			} else {
				log.V(3).Info("secret %s has invalid DNS names, the expected names are: %v", secretName, dnsNames)
			}
		} else if err != nil {
			return nil, err
		}
		invalid := cert.NotAfter.Before(time.Now()) || cert.NotBefore.After(time.Now())
		if invalid && !strings.HasPrefix(cert.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) {
			return nil, fmt.Errorf("secret %s is invalid", secretName)
		}

		// Create a new secret if the secret has invalid or has been signed by an older/replaced CA.
		createNew = createNew || invalid
	}

	if createNew {
		if cm.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(cm, secretName, dnsNames), nil
		}
		tlsCfg, err := cm.MakeServerCertForDuration(sets.NewString(dnsNames...), rmeta.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
		if err != nil {
			return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
		}
		keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
		if err := tlsCfg.WriteCertConfig(crtContent, keyContent); err != nil {
			return nil, err
		}
		kp.privateKeyPem, kp.certificatePEM = keyContent.Bytes(), crtContent.Bytes()
	}
	return kp, nil
}

// Issued returns true if the provided certificate was signed by certificateManager and returns false for user provided KeyPairs or Certificate Management.
func (cm *certificateManager) Issued(certPem []byte) bool {
	if cm.CertificateManagement() == nil && len(certPem) != 0 {
		x509Cert, err := parseCertificate(certPem)
		if err != nil {
			return false
		}
		return string(x509Cert.AuthorityKeyId) == string(cm.Certificate.AuthorityKeyId)
	}
	return false
}

// GetCertificate returns a Certificate. If the certificate is not found a k8s.io NotFound error is returned.
func (cm *certificateManager) GetCertificate(cli client.Client, secretName, secretNamespace string) (render.Certificate, error) {
	if cm.CertificateManagement() != nil {
		return NewCertificate(secretName, nil), nil
	}
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		return nil, err
	}
	_, cert := getKeyCertPEM(secret)
	if len(cert) == 0 {
		return nil, fmt.Errorf("secret %s/%s is missing a certificate", secret.Namespace, secret.Name)
	}
	x509Cert, err := parseCertificate(cert)
	if err != nil {
		return nil, err
	}
	if x509Cert.NotAfter.Before(time.Now()) || x509Cert.NotBefore.After(time.Now()) {
		return nil, fmt.Errorf("secret %s is not valid at this date", secretName)
	}
	return NewCertificate(secretName, cert), nil
}

// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, a k8s.io NotFound error is returned.
func (cm *certificateManager) GetKeyPair(cli client.Client, secretName, secretNamespace string) (render.KeyPair, error) {
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		if !kerrors.IsNotFound(err) && cm.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(cm, secretName, nil), nil
		}
		return nil, nil
	}
	keyPEM, certPEM := getKeyCertPEM(secret)
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return nil, fmt.Errorf("secret %s/%s is missing a certificate", secret.Namespace, secret.Name)
	}
	cert, err := parseCertificate(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}
	if cert.NotAfter.Before(time.Now()) || cert.NotBefore.After(time.Now()) {
		return nil, fmt.Errorf("secret %s is not valid at this date", secretName)
	}
	return &keyPair{
		ca:             cm,
		name:           secretName,
		privateKeyPem:  keyPEM,
		certificatePEM: certPEM,
	}, nil
}

// CertificateManagement returns the CertificateManagement object or nil if it is not configured.
func (cm *certificateManager) CertificateManagement() *operatorv1.CertificateManagement {
	return cm.keyPair.CertificateManagement
}

type keyPair struct {
	csrImage       string
	name           string
	privateKeyPem  []byte
	certificatePEM []byte
	clusterDomain  string
	*operatorv1.CertificateManagement
	dnsNames                 []string
	useCertificateManagement bool
	ca                       render.CertificateManager
}

func (k *keyPair) CertificatePEM() []byte {
	return k.certificatePEM
}

func (k *keyPair) Name() string {
	return k.name
}

// UseCertificateManagement is true if this secret is not BYO and certificate management is used to provide the a pair to a pod.
func (k *keyPair) UseCertificateManagement() bool {
	return k.useCertificateManagement
}

// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
func (k *keyPair) BYO() bool {
	return k.useCertificateManagement == false && (k.ca != nil && !k.ca.Issued(k.certificatePEM))
}

// certificateManagementKeyPair returns a KeyPair for to be used when certificate management is used to provide a key pair to a pod.
func certificateManagementKeyPair(ca *certificateManager, secretName string, dnsNames []string) *keyPair {
	return &keyPair{
		name:                     secretName,
		CertificateManagement:    ca.CertificateManagement(),
		useCertificateManagement: true,
		dnsNames:                 dnsNames,
		ca:                       ca,
		csrImage:                 ca.csrImage,
	}
}

// NewKeyPair returns  a KeyPair, which wraps a Secret object that contains a private key and a certificate. Whether certificate
// management is configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
func NewKeyPair(ca render.CertificateManager, secret *corev1.Secret, dnsNames []string, clusterDomain string) (render.KeyPair, error) {
	return &keyPair{
		name:           secret.Name,
		privateKeyPem:  secret.Data[corev1.TLSPrivateKeyKey],
		certificatePEM: secret.Data[corev1.TLSCertKey],
		dnsNames:       dnsNames,
		clusterDomain:  clusterDomain,
		ca:             ca,
	}, nil
}

func getKeyCertPEM(secret *corev1.Secret) ([]byte, []byte) {
	const (
		legacySecretCertName  = "cert" // Formerly known as render.ManagerSecretCertName
		legacySecretKeyName   = "key"  // Formerly known as render.ManagerSecretKeyName
		legacySecretKeyName2  = "apiserver.key"
		legacySecretCertName2 = "apiserver.crt"
		legacySecretKeyName3  = "key.key"  // Formerly used for Felix and Typha.
		legacySecretCertName3 = "cert.crt" // Formerly used for Felix and Typha.
	)
	data := secret.Data
	for keyField, certField := range map[string]string{
		corev1.TLSPrivateKeyKey: corev1.TLSCertKey,
		legacySecretKeyName:     legacySecretCertName,
		legacySecretKeyName2:    legacySecretCertName2,
		legacySecretKeyName3:    legacySecretCertName3,
	} {
		key, cert := data[keyField], data[certField]
		if len(key) > 0 && len(cert) > 0 {
			return key, cert
		}
	}
	return nil, nil
}

func (k *keyPair) Secret(namespace string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: k.Name(), Namespace: namespace},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: k.privateKeyPem,
			corev1.TLSCertKey:       k.certificatePEM,
		},
	}
}

func (k *keyPair) HashAnnotationKey() string {
	return fmt.Sprintf("hash.operator.tigera.io/%s", k.Name())
}

func (k *keyPair) HashAnnotationValue() string {
	if k.CertificateManagement != nil {
		return ""
	}
	return rmeta.AnnotationHash(rmeta.AnnotationHash(k.certificatePEM))
}

func (k *keyPair) Volume() corev1.Volume {
	volumeSource := certificatemanagement.CertificateVolumeSource(k.CertificateManagement, k.Name())
	return corev1.Volume{
		Name:         k.Name(),
		VolumeSource: volumeSource,
	}
}

func (k *keyPair) VolumeMountCertificateFilePath() string {
	return fmt.Sprintf("/%s/%s", k.Name(), corev1.TLSCertKey)
}

func (k *keyPair) VolumeMountKeyFilePath() string {
	return fmt.Sprintf("/%s/%s", k.Name(), corev1.TLSPrivateKeyKey)
}

func (k *keyPair) VolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      k.Name(),
		MountPath: fmt.Sprintf("/%s", k.Name()),
		ReadOnly:  true,
	}
}

// InitContainer contains an init container for making a CSR. is only applicable when certificate management is enabled.
func (k *keyPair) InitContainer(namespace string) corev1.Container {
	initContainer := certificatemanagement.CreateCSRInitContainer(
		k.CertificateManagement,
		k.csrImage,
		k.Name(),
		k.dnsNames[0],
		corev1.TLSPrivateKeyKey,
		corev1.TLSCertKey,
		k.dnsNames,
		namespace)
	initContainer.Name = fmt.Sprintf("%s-%s", k.Name(), initContainer.Name)
	return initContainer
}

func parseCertificate(certBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return nil, errInvalidCertNoPEMData
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func hasExpectedDNSNames(cert *x509.Certificate, expectedDNSNames []string) error {
	dnsNames := sets.NewString(cert.DNSNames...)
	if dnsNames.HasAll(expectedDNSNames...) {
		return nil
	}
	return errInvalidCertDNSNames
}

func NewCertificate(name string, pem []byte) render.Certificate {
	return &certificate{name: name, pem: pem}
}

type certificate struct {
	name string
	pem  []byte
}

func (c *certificate) CertificatePEM() []byte {
	return c.pem
}

func (c *certificate) Name() string {
	return c.name
}
