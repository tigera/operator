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

package certificatemanagement

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tigera/operator/pkg/controller/status"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/crypto"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

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
	CASecretName                = "tigera-ca-private"
	TrustedCertConfigMapName    = "tigera-ca-bundle"
	TrustedCertConfigMapKeyName = "tigera-ca-bundle.crt"
	TrustedCertVolumeMountPath  = "/etc/pki/tls/certs/"
	TrustedCertBundleMountPath  = "/etc/pki/tls/certs/tigera-ca-bundle.crt"
)

// CertificateManager can sign new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
type CertificateManager interface {
	// CertificateManagement returns the CertificateManagement object or nil if it is not configured.
	CertificateManagement() *operatorv1.CertificateManagement
	// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, nil is returned.
	GetKeyPair(cli client.Client, secretName, secretNamespace string) (KeyPair, error)
	// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
	GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (KeyPair, error)
	// GetCertificate returns a Certificate. If the certificate is not found a k8s.io NotFound error is returned.
	GetCertificate(cli client.Client, secretName, secretNamespace string) (Certificate, error)
	// Issued returns true if the provided certificate was signed by CertificateManager and returns false for user provided KeyPairs or Certificate Management.
	Issued(certificate Certificate) bool
	AddToStatusManager(manager status.StatusManager, namespace string)
	KeyPair
}

// KeyPair wraps a Secret object that contains a private key and a certificate. Whether CertificateManagement is
// configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
type KeyPair interface {
	//UseCertificateManagement returns true if this key pair was not user provided and certificate management has been configured.
	UseCertificateManagement() bool
	// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
	BYO() bool
	InitContainer(namespace, csrImage string) corev1.Container
	VolumeMount(folder string) corev1.VolumeMount
	Volume() corev1.Volume
	// HasSkipRenderInOperatorNamespace Default: false. If true, this will avoid (re-)rendering a secret in the operator namespace and avoid changing an ownerRef.
	HasSkipRenderInOperatorNamespace() bool
	// SetSkipRenderInOperatorNamespace will avoid (re-)rendering a secret in the operator namespace and avoid changing an ownerRef.
	SetSkipRenderInOperatorNamespace()
	Certificate
}

// Certificate wraps the certificate. Combine this with a TrustedBundle, to mount a trusted certificate bundle to a pod.
type Certificate interface {
	X509Certificate() *x509.Certificate
	Secret(namespace string) *corev1.Secret
	HashAnnotationKey() string
	HashAnnotationValue() string
}

// TrustedBundle is used to create a trusted certificate bundle of the CertificateManager CA and 0 or more Certificates.
type TrustedBundle interface {
	MountPath() string
	ConfigMap(namespace string) *corev1.ConfigMap
	HashAnnotations() map[string]string
	VolumeMount() corev1.VolumeMount
	Volume() corev1.Volume
	//AddPEM adds a PEM block to the certificate bundle.
	AddPEM(annotationName string, pem []byte)
	AddCertificates(certificates ...Certificate)
}

var (
	log                     = logf.Log.WithName("tls")
	errInvalidCertDNSNames  = errors.New("cert has the wrong DNS names")
	errInvalidCertNoPEMData = errors.New("cert has no PEM data")
)

type trustedBundle struct {
	certificateManager CertificateManager
	pem                []byte
	annotations        map[string]string
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
func CreateTrustedBundle(ca CertificateManager, certificates ...Certificate) TrustedBundle {
	secret := ca.Secret("")
	bundle := &trustedBundle{certificateManager: ca,
		pem: []byte(fmt.Sprintf("# certificate name: %s\n%s\n\n", secret.Name, string(secret.Data[corev1.TLSCertKey]))),
		annotations: map[string]string{
			ca.HashAnnotationKey(): ca.HashAnnotationValue(),
		}}
	bundle.AddCertificates(certificates...)
	return bundle
}

// AddCertificates Adds the PEM blocks of the certificates to the bundle.
func (t *trustedBundle) AddCertificates(certificates ...Certificate) {
	pemBuf := bytes.Buffer{}
	pemBuf.Write(t.pem) // err is always nil.
	for _, certificate := range certificates {
		if certificate != nil && certificate.X509Certificate() != nil && !t.certificateManager.Issued(certificate) {
			t.annotations[certificate.HashAnnotationKey()] = certificate.HashAnnotationValue()
			secret := certificate.Secret("")
			pemBuf.WriteString(fmt.Sprintf("# certificate name: %s\n%s\n\n",
				secret.Name, string(secret.Data[corev1.TLSCertKey]))) // err is always nil
		}
	}
	t.pem = pemBuf.Bytes()
}

func (t *trustedBundle) MountPath() string {
	return TrustedCertBundleMountPath
}

func (t *trustedBundle) HashAnnotations() map[string]string {
	return t.annotations
}

func (t *trustedBundle) VolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      TrustedCertConfigMapName,
		MountPath: TrustedCertVolumeMountPath,
		ReadOnly:  true,
	}
}

func (t *trustedBundle) Volume() corev1.Volume {
	return corev1.Volume{
		Name: TrustedCertConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: TrustedCertConfigMapName},
			},
		},
	}
}

func (t *trustedBundle) ConfigMap(namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TrustedCertConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			TrustedCertConfigMapKeyName: string(t.pem),
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
	*crypto.CA
	keyPair
}

// CreateCertificateManager creates a signer of new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
func CreateCertificateManager(cli client.Client, certificateManagement *operatorv1.CertificateManagement, clusterDomain string) (CertificateManager, error) {
	var cryptoCA *crypto.CA
	var caSecret *corev1.Secret
	if certificateManagement != nil {
		caSecret = &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      CASecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				corev1.TLSCertKey: certificateManagement.CACert,
			},
		}
	} else {
		caSecret = &corev1.Secret{}
		err := cli.Get(context.Background(), types.NamespacedName{
			Name:      CASecretName,
			Namespace: common.OperatorNamespace(),
		}, caSecret)
		if err != nil && !kerrors.IsNotFound(err) {
			return nil, err
		}
		if caSecret == nil ||
			len(caSecret.Data) == 0 ||
			len(caSecret.Data[corev1.TLSPrivateKeyKey]) == 0 ||
			len(caSecret.Data[corev1.TLSCertKey]) == 0 {
			cryptoCA, err = MakeCA(rmeta.TigeraOperatorCAIssuerPrefix)
			if err != nil {
				return nil, err
			}
			caSecret, err = getSecretFromTLSConfig(cryptoCA.Config, CASecretName, common.OperatorNamespace())
			if err != nil {
				return nil, err
			}
		} else {
			cryptoCA, err = crypto.GetCAFromBytes(caSecret.Data[corev1.TLSCertKey], caSecret.Data[corev1.TLSPrivateKeyKey])
		}
	}
	x509Cert, err := parseCertificate(caSecret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}
	return &certificateManager{
		CA: cryptoCA,
		keyPair: keyPair{
			Certificate:           x509Cert,
			secret:                caSecret,
			clusterDomain:         clusterDomain,
			CertificateManagement: certificateManagement,
		},
	}, nil
}

func (cm *certificateManager) AddToStatusManager(statusManager status.StatusManager, namespace string) {
	if cm.CertificateManagement() != nil {
		statusManager.AddCertificateSigningRequests(namespace, map[string]string{"k8s-app": namespace})
	} else {
		statusManager.RemoveCertificateSigningRequests(namespace)
	}
}

// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
func (cm *certificateManager) GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (KeyPair, error) {
	secret := &corev1.Secret{}
	kp := &keyPair{
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
		err = standardizeFields(secret)
		if err != nil {
			return nil, err
		}
		kp.Certificate, err = parseCertificate(secret.Data[corev1.TLSCertKey])
		if err != nil {
			return nil, err
		}
		err = hasExpectedDNSNames(kp.Certificate, dnsNames)
		if err == errInvalidCertDNSNames {
			if strings.HasPrefix(kp.Certificate.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) && !cm.Issued(kp) {
				createNew = true
			} else {
				log.V(3).Info("secret %s has invalid DNS names, the expected names are: %v", secretName, dnsNames)
			}
		} else if err != nil {
			return nil, err
		}
		invalid := kp.Certificate.NotAfter.Before(time.Now()) || kp.Certificate.NotBefore.After(time.Now())
		if invalid && !strings.HasPrefix(kp.Certificate.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) {
			return nil, fmt.Errorf("secret %s is invalid", secretName)
		}
		// Create a new secret if the secret has invalid or has been signed by an older/replaced CA.
		createNew = createNew || invalid
	}

	if createNew {
		if cm.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(cm, secretName, secretNamespace, dnsNames), nil
		}
		tlsCfg, err := cm.MakeServerCertForDuration(sets.NewString(dnsNames...), rmeta.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
		if err != nil {
			return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
		}
		secret, err = getSecretFromTLSConfig(tlsCfg, secretName, secretNamespace)
		if err != nil {
			return nil, fmt.Errorf("unable to create secret: %s", err)
		}
		kp.Certificate, err = parseCertificate(secret.Data[corev1.TLSCertKey])
		if err != nil {
			return nil, err
		}
	}
	kp.secret = secret
	return kp, nil
}

// Issued returns true if the provided certificate was signed by certificateManager and returns false for user provided KeyPairs or Certificate Management.
func (cm *certificateManager) Issued(cert Certificate) bool {
	return cm.CertificateManagement() == nil && cert != nil &&
		string(cert.X509Certificate().AuthorityKeyId) == string((cm.X509Certificate()).AuthorityKeyId)
}

// GetCertificate returns a Certificate. If the certificate is not found a k8s.io NotFound error is returned.
func (cm *certificateManager) GetCertificate(cli client.Client, secretName, secretNamespace string) (Certificate, error) {
	if cm.CertificateManagement() != nil {
		return certificateManagementKeyPair(cm, secretName, secretNamespace, nil), nil
	}
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		return nil, err
	}
	err = standardizeFields(secret)
	if err != nil {
		return nil, err
	}
	x509Cert, err := parseCertificate(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}
	if x509Cert.NotAfter.Before(time.Now()) || x509Cert.NotBefore.After(time.Now()) {
		return nil, fmt.Errorf("secret %s is not valid at this date", secretName)
	}
	return &keyPair{ca: cm, Certificate: x509Cert, secret: secret}, nil
}

// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, a k8s.io NotFound error is returned.
func (cm *certificateManager) GetKeyPair(cli client.Client, secretName, secretNamespace string) (KeyPair, error) {
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		if !kerrors.IsNotFound(err) && cm.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(cm, secretName, secretNamespace, nil), nil
		}
		return nil, nil
	}
	err = standardizeFields(secret)
	if err != nil {
		return nil, err
	}
	certificate, err := parseCertificate(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}
	if certificate.NotAfter.Before(time.Now()) || certificate.NotBefore.After(time.Now()) {
		return nil, fmt.Errorf("secret %s is not valid at this date", secretName)
	}
	return &keyPair{
		ca:          cm,
		secret:      secret,
		Certificate: certificate,
	}, nil
}

// CertificateManagement returns the CertificateManagement object or nil if it is not configured.
func (cm *certificateManager) CertificateManagement() *operatorv1.CertificateManagement {
	return cm.keyPair.CertificateManagement
}

type keyPair struct {
	*x509.Certificate
	secret        *corev1.Secret
	clusterDomain string
	*operatorv1.CertificateManagement
	dnsNames                      []string
	useCertificateManagement      bool
	ca                            CertificateManager
	skipRenderInOperatorNamespace bool
}

// UseCertificateManagement is true if this secret is not BYO and certificate management is used to provide the a pair to a pod.
func (c *keyPair) UseCertificateManagement() bool {
	return c.useCertificateManagement
}

// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
func (c *keyPair) BYO() bool {
	return c.useCertificateManagement == false && !c.ca.Issued(c)
}

// HasSkipRenderInOperatorNamespace Default: false. If true, this will avoid (re-)rendering a secret in the operator namespace and avoid changing an ownerRef.
func (c *keyPair) HasSkipRenderInOperatorNamespace() bool {
	return c.BYO() || c.skipRenderInOperatorNamespace
}

// SetSkipRenderInOperatorNamespace will avoid (re-)rendering a secret in the operator namespace and avoid changing an ownerRef.
func (c *keyPair) SetSkipRenderInOperatorNamespace() {
	c.skipRenderInOperatorNamespace = true
}

func (c *keyPair) X509Certificate() *x509.Certificate {
	return c.Certificate
}

// certificateManagementKeyPair returns a KeyPair for to be used when certificate management is used to provide a key pair to a pod.
func certificateManagementKeyPair(ca *certificateManager, secretName, secretNamespace string, dnsNames []string) *keyPair {
	return &keyPair{
		secret: &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: secretNamespace}},
		Certificate:              ca.Certificate,
		CertificateManagement:    ca.CertificateManagement(),
		useCertificateManagement: true,
		dnsNames:                 dnsNames,
		ca:                       ca,
	}
}

// NewKeyPair returns  a KeyPair, which wraps a Secret object that contains a private key and a certificate. Whether certificate
// management is configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
func NewKeyPair(ca CertificateManager, secret *corev1.Secret, dnsNames []string, clusterDomain string) (KeyPair, error) {
	certificate, err := parseCertificate(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}
	return &keyPair{
		secret:        secret,
		dnsNames:      dnsNames,
		clusterDomain: clusterDomain,
		Certificate:   certificate,
		ca:            ca,
	}, nil
}

// standardizeFields makes sure that the fields corev1.TLSPrivateKeyKey and corev1.TLSCertKey are always present.
func standardizeFields(secret *corev1.Secret) error {
	const (
		legacySecretCertName  = "cert" // Formerly known as render.ManagerSecretCertName
		legacySecretKeyName   = "key"  // Formerly known as render.ManagerSecretKeyName
		legacySecretKeyName2  = "apiserver.key"
		legacySecretCertName2 = "apiserver.crt"
		legacySecretKeyName3  = "key.key"  // Formerly used for Felix and Typha.
		legacySecretCertName3 = "cert.crt" // Formerly used for Felix and Typha.
	)
	data := secret.Data
	// Some secrets described in our docs do not use the corev1 constants for SecretTypeTLS.
	key, cert := data[corev1.TLSPrivateKeyKey], data[corev1.TLSCertKey]
	standardizeFn := func(legacyKeyField, LegacyCertField string) {
		legacyKey, legacyCert := data[legacyKeyField], data[LegacyCertField]
		if len(legacyKey) > 0 && len(key) == 0 && len(legacyCert) > 0 && len(cert) == 0 {
			data[corev1.TLSPrivateKeyKey] = legacyKey
			data[corev1.TLSCertKey] = legacyCert
		}
	}

	standardizeFn(legacySecretKeyName, legacySecretCertName)
	standardizeFn(legacySecretKeyName2, legacySecretCertName2)
	standardizeFn(legacySecretKeyName3, legacySecretCertName3)

	if len(data[corev1.TLSCertKey]) == 0 {
		return fmt.Errorf("secret %s/%s is missing a certificate", secret.Namespace, secret.Name)
	}
	return nil
}

func (c *keyPair) Secret(namespace string) *corev1.Secret {
	secret := c.secret.DeepCopy()
	secret.ObjectMeta = metav1.ObjectMeta{Name: secret.Name, Namespace: namespace}
	return secret
}

func (c *keyPair) HashAnnotationKey() string {
	return fmt.Sprintf("hash.operator.tigera.io/%s", c.secret.Name)
}

func (c *keyPair) HashAnnotationValue() string {
	if c.CertificateManagement != nil {
		return ""
	}
	return rmeta.AnnotationHash(c.Certificate.SubjectKeyId)
}

func (c *keyPair) Volume() corev1.Volume {
	volumeSource := CertificateVolumeSource(c.CertificateManagement, c.secret.Name)
	return corev1.Volume{
		Name:         c.secret.Name,
		VolumeSource: volumeSource,
	}
}

func (c *keyPair) VolumeMount(path string) corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      c.secret.Name,
		MountPath: path,
		ReadOnly:  true,
	}
}

// InitContainer contains an init container for making a CSR. is only applicable when certificate management is enabled.
func (c *keyPair) InitContainer(namespace, csrImage string) corev1.Container {
	initContainer := CreateCSRInitContainer(
		c.CertificateManagement,
		csrImage,
		c.secret.Name,
		c.dnsNames[0],
		corev1.TLSPrivateKeyKey,
		corev1.TLSCertKey,
		c.dnsNames,
		namespace)
	initContainer.Name = fmt.Sprintf("%s-%s", c.secret.Name, initContainer.Name)
	return initContainer
}

func getSecretFromTLSConfig(tls *crypto.TLSCertificateConfig, secretName, secretNamespace string) (*corev1.Secret, error) {
	keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
	if err := tls.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyContent.Bytes(),
			corev1.TLSCertKey:       crtContent.Bytes(),
		},
	}, nil
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
