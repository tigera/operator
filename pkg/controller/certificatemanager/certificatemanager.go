// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

package certificatemanager

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("tls")

func ErrInvalidCertDNSNames(secretName, secretNamespace string) error {
	log.V(1).Info("Certificate has wrong DNS names", "namespace", secretNamespace, "name", secretName)
	return fmt.Errorf("certificate %s/%s has the wrong DNS names", secretNamespace, secretName)
}

func errNoPrivateKeyPEM(secretName, secretNamespace string) error {
	return fmt.Errorf("key pair %s/%s is missing a private key", secretNamespace, secretName)
}

func errNoCertificatePEM(secretName, secretNamespace string) error {
	return fmt.Errorf("certificate PEM is missing for %s/%s ", secretNamespace, secretName)
}

type certificateManager struct {
	*x509.Certificate
	*crypto.CA
	keyPair *certificatemanagement.KeyPair
}

// CertificateManager can sign new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
type CertificateManager interface {
	// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, nil is returned.
	GetKeyPair(cli client.Client, secretName, secretNamespace string) (certificatemanagement.KeyPairInterface, error)
	// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
	GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error)
	// GetCertificate returns a Certificate. If the certificate is not found, nil is returned.
	GetCertificate(cli client.Client, secretName, secretNamespace string) (certificatemanagement.CertificateInterface, error)
	// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
	// It will include:
	// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
	CreateTrustedBundle(certificates ...certificatemanagement.CertificateInterface) certificatemanagement.TrustedBundle
	// CreateTrustedBundleWithSystemRootCertificates creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
	// It will include:
	// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
	// - A system root certificate bundle in /etc/pki/tls/certs/ca-bundle.crt.
	CreateTrustedBundleWithSystemRootCertificates(certificates ...certificatemanagement.CertificateInterface) (certificatemanagement.TrustedBundle, error)
	// AddToStatusManager lets the status manager monitor pending CSRs if the certificate management is enabled.
	AddToStatusManager(manager status.StatusManager, namespace string)
	// KeyPair Returns the CA KeyPairInterface, so it can be rendered in the operator namespace.
	KeyPair() certificatemanagement.KeyPairInterface
}

// Create creates a signer of new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
func Create(cli client.Client, installation *operatorv1.InstallationSpec, clusterDomain, ns string) (CertificateManager, error) {
	var (
		cryptoCA                      *crypto.CA
		csrImage                      string
		privateKeyPEM, certificatePEM []byte
		certificateManagement         *operatorv1.CertificateManagement
		err                           error
	)

	if installation != nil && installation.CertificateManagement != nil {
		// Configured to use certificate management. Get the CACert from
		// the installation spec.
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
		// Using operator-managed certificates. Check to see if we have already provisioned one.
		caSecret := &corev1.Secret{}
		k := types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: ns}
		if err = cli.Get(context.Background(), k, caSecret); err != nil && !kerrors.IsNotFound(err) {
			return nil, err
		}

		if len(caSecret.Data) == 0 ||
			len(caSecret.Data[corev1.TLSPrivateKeyKey]) == 0 ||
			len(caSecret.Data[corev1.TLSCertKey]) == 0 {
			// No existing CA data - we need to generate a new one.
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
			// Found an existing CA - use that.
			privateKeyPEM, certificatePEM = caSecret.Data[corev1.TLSPrivateKeyKey], caSecret.Data[corev1.TLSCertKey]
			cryptoCA, err = crypto.GetCAFromBytes(certificatePEM, privateKeyPEM)
			if err != nil {
				return nil, err
			}
		}
	}

	// At this point, we've located an existing CA or genrated a new one. Build a certificateManager
	// instance based on it.
	x509Cert, err := certificatemanagement.ParseCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	return &certificateManager{
		CA:          cryptoCA,
		Certificate: x509Cert,
		keyPair: &certificatemanagement.KeyPair{
			Name:                  certificatemanagement.CASecretName,
			PrivateKeyPEM:         privateKeyPEM,
			CertificatePEM:        certificatePEM,
			CSRImage:              csrImage,
			ClusterDomain:         clusterDomain,
			CertificateManagement: certificateManagement,
		},
	}, nil
}

func (cm *certificateManager) KeyPair() certificatemanagement.KeyPairInterface {
	return cm.keyPair
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
func (cm *certificateManager) GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error) {
	keyPair, x509Cert, err := cm.getKeyPair(cli, secretName, secretNamespace, false)
	if keyPair != nil && keyPair.UseCertificateManagement() {
		return certificateManagementKeyPair(cm, secretName, dnsNames), nil
	}
	if err != nil && !kerrors.IsNotFound(err) {
		return nil, err
	} else if keyPair != nil {
		err = HasExpectedDNSNames(secretName, secretNamespace, x509Cert, dnsNames)
		if err == nil {
			return keyPair, nil
		} else if keyPair.BYO() {
			log.V(3).Info("secret %s has invalid DNS names, the expected names are: %v", secretName, dnsNames)
			return keyPair, nil
		}
	} else if keyPair == nil {
		log.V(1).Info("Keypair wasn't found, create a new one", "namespace", secretNamespace, "name", secretName)
	}

	// If we reach here, it means we need to create a new KeyPair.
	tlsCfg, err := cm.MakeServerCertForDuration(sets.NewString(dnsNames...), rmeta.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
	}
	keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
	if err := tlsCfg.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	return &certificatemanagement.KeyPair{
		Issuer:         cm.keyPair,
		Name:           secretName,
		PrivateKeyPEM:  keyContent.Bytes(),
		CertificatePEM: crtContent.Bytes(),
		DNSNames:       dnsNames,
	}, nil
}

// getKeyPair is an internal convenience method to retrieve a keypair or a certificate.
func (cm *certificateManager) getKeyPair(cli client.Client, secretName, secretNamespace string, readCertOnly bool) (certificatemanagement.KeyPairInterface, *x509.Certificate, error) {
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		if kerrors.IsNotFound(err) {
			if cm.keyPair.CertificateManagement != nil {
				// When certificate management is enabled, we expect that in most cases no secret will be present.
				return certificateManagementKeyPair(cm, secretName, nil), nil, nil
			}
			return nil, nil, nil
		}
		return nil, nil, err
	}
	keyPEM, certPEM := getKeyCertPEM(secret)
	if !readCertOnly {
		if len(keyPEM) == 0 {
			return nil, nil, errNoPrivateKeyPEM(secretName, secretNamespace)
		}
	}
	if len(certPEM) == 0 {
		return nil, nil, errNoCertificatePEM(secretName, secretNamespace)
	}
	x509Cert, err := certificatemanagement.ParseCertificate(certPEM)
	if err != nil {
		return nil, nil, err
	}

	if x509Cert.NotAfter.Before(time.Now()) || x509Cert.NotBefore.After(time.Now()) {
		if !readCertOnly && strings.HasPrefix(x509Cert.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) {
			if cm.keyPair.CertificateManagement != nil {
				// When certificate management is enabled, we can simply return a certificate management key pair;
				// the old secret will be deleted automatically.
				return certificateManagementKeyPair(cm, secretName, nil), nil, nil
			}
			// We return nil, so a new secret will be created for expired (legacy) operator signed secrets.
			return nil, nil, nil
		}
		// We return an error for byo secrets.
		return nil, nil, fmt.Errorf("secret %s is not valid at this date", secretName)
	}
	var issuer certificatemanagement.KeyPairInterface
	if x509Cert.Issuer.CommonName == rmeta.TigeraOperatorCAIssuerPrefix {
		if cm.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(cm, secretName, nil), nil, nil
		}
		if string(x509Cert.AuthorityKeyId) == string(cm.AuthorityKeyId) {
			issuer = cm.keyPair
		} else {
			if !readCertOnly {
				// We want to return nothing, so a new secret will be created to overwrite this one.
				return nil, nil, nil
			}
			// We treat the certificate as a BYO secret, because this may be a certificate created by a management cluster
			// and used inside a managed cluster. If it is not, it should get updated automatically when readCertOnly=false.
			issuer = nil
		}
	}
	return &certificatemanagement.KeyPair{
		Issuer:         issuer,
		Name:           secretName,
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
		OriginalSecret: secret,
	}, x509Cert, nil
}

// GetCertificate returns a Certificate. If the certificate is not found or outdated, a k8s.io NotFound error is returned.
func (cm *certificateManager) GetCertificate(cli client.Client, secretName, secretNamespace string) (certificatemanagement.CertificateInterface, error) {
	keyPair, _, err := cm.getKeyPair(cli, secretName, secretNamespace, true)
	return keyPair, err
}

// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, nil is returned.
func (cm *certificateManager) GetKeyPair(cli client.Client, secretName, secretNamespace string) (certificatemanagement.KeyPairInterface, error) {
	keyPair, _, err := cm.getKeyPair(cli, secretName, secretNamespace, false)
	return keyPair, err
}

// CertificateManagement returns the CertificateManagement object or nil if it is not configured.
func (cm *certificateManager) CertificateManagement() *operatorv1.CertificateManagement {
	return cm.keyPair.CertificateManagement
}

func getKeyCertPEM(secret *corev1.Secret) ([]byte, []byte) {
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

// certificateManagementKeyPair returns a KeyPair for to be used when certificate management is used to provide a key pair to a pod.
func certificateManagementKeyPair(ca *certificateManager, secretName string, dnsNames []string) *certificatemanagement.KeyPair {
	return &certificatemanagement.KeyPair{
		Name:                  secretName,
		CertificateManagement: ca.CertificateManagement(),
		DNSNames:              dnsNames,
		CSRImage:              ca.keyPair.CSRImage,
	}
}

func HasExpectedDNSNames(secretName, secretNamespace string, cert *x509.Certificate, expectedDNSNames []string) error {
	dnsNames := sets.NewString(cert.DNSNames...)
	if dnsNames.HasAll(expectedDNSNames...) {
		return nil
	}
	return ErrInvalidCertDNSNames(secretName, secretNamespace)
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
func (cm *certificateManager) CreateTrustedBundle(certificates ...certificatemanagement.CertificateInterface) certificatemanagement.TrustedBundle {
	return certificatemanagement.CreateTrustedBundle(append([]certificatemanagement.CertificateInterface{cm.keyPair}, certificates...)...)
}

// CreateTrustedBundleWithSystemRootCertificates creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
// - A system root certificate bundle in /etc/pki/tls/certs/ca-bundle.crt.
func (cm *certificateManager) CreateTrustedBundleWithSystemRootCertificates(certificates ...certificatemanagement.CertificateInterface) (certificatemanagement.TrustedBundle, error) {
	return certificatemanagement.CreateTrustedBundleWithSystemRootCertificates(append([]certificatemanagement.CertificateInterface{cm.keyPair}, certificates...)...)
}
