package certificatemanager

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
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
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	log                    = logf.Log.WithName("tls")
	ErrInvalidCertDNSNames = errors.New("certificate has the wrong DNS names")
	errNoPrivateKeyPEM     = errors.New("key pair is missing a private key")
	errNoCertificatePEM    = errors.New("certificate PEM is missing")
	errCreatedByOldCA      = errors.New("certificate was created by an older ca")
)

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
	// AddToStatusManager lets the status manager monitor pending CSRs if the certificate management is enabled.
	AddToStatusManager(manager status.StatusManager, namespace string)
	KeyPair() certificatemanagement.KeyPairInterface
}

// Create creates a signer of new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
func Create(cli client.Client, installation *operatorv1.InstallationSpec, clusterDomain string) (CertificateManager, error) {
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
			Name:      certificatemanagement.CASecretName,
			Namespace: common.OperatorNamespace(),
		}, caSecret)
		if err != nil && !kerrors.IsNotFound(err) {
			return nil, err
		}
		if len(caSecret.Data) == 0 ||
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
	keyPair, x509Cert, err := cm.getKeyPair(cli, secretName, secretNamespace, true)
	if keyPair != nil && cm.keyPair.CertificateManagement != nil {
		return certificateManagementKeyPair(cm, secretName, dnsNames), nil
	}
	if err != nil && !kerrors.IsNotFound(err) {
		return nil, err
	} else if keyPair != nil {
		err = HasExpectedDNSNames(x509Cert, dnsNames)
		if err == nil {
			return keyPair, nil
		} else if keyPair.BYO() {
			log.V(3).Info("secret %s has invalid DNS names, the expected names are: %v", secretName, dnsNames)
			return keyPair, nil
		}
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
func (cm *certificateManager) getKeyPair(cli client.Client, secretName, secretNamespace string, mustIncludePrivateKey bool) (certificatemanagement.KeyPairInterface, *x509.Certificate, error) {
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		if kerrors.IsNotFound(err) {
			if cm.keyPair.CertificateManagement != nil {
				return certificateManagementKeyPair(cm, secretName, nil), nil, nil
			}
			return nil, nil, nil
		}
		return nil, nil, err
	}
	keyPEM, certPEM := getKeyCertPEM(secret)
	if mustIncludePrivateKey {
		if len(keyPEM) == 0 {
			return nil, nil, errNoPrivateKeyPEM
		}
	}
	if len(certPEM) == 0 {
		return nil, nil, errNoCertificatePEM
	}
	x509Cert, err := certificatemanagement.ParseCertificate(certPEM)
	if err != nil {
		return nil, nil, err
	}
	if x509Cert.NotAfter.Before(time.Now()) || x509Cert.NotBefore.After(time.Now()) {
		return nil, nil, fmt.Errorf("secret %s is not valid at this date", secretName)
	}
	var issuer certificatemanagement.KeyPairInterface
	if x509Cert.Issuer.CommonName == rmeta.TigeraOperatorCAIssuerPrefix {
		if string(x509Cert.AuthorityKeyId) == string(cm.AuthorityKeyId) {
			issuer = cm.keyPair
		} else {
			if mustIncludePrivateKey {
				return nil, nil, nil
			}
			return nil, nil, errCreatedByOldCA
		}
	}
	return &certificatemanagement.KeyPair{
		Issuer:         issuer,
		Name:           secretName,
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
	}, x509Cert, nil

}

// GetCertificate returns a Certificate. If the certificate is not found or outdated, a k8s.io NotFound error is returned.
func (cm *certificateManager) GetCertificate(cli client.Client, secretName, secretNamespace string) (certificatemanagement.CertificateInterface, error) {
	keyPair, _, err := cm.getKeyPair(cli, secretName, secretNamespace, false)
	return keyPair, err
}

// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, nil is returned.
func (cm *certificateManager) GetKeyPair(cli client.Client, secretName, secretNamespace string) (certificatemanagement.KeyPairInterface, error) {
	keyPair, _, err := cm.getKeyPair(cli, secretName, secretNamespace, true)
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

func HasExpectedDNSNames(cert *x509.Certificate, expectedDNSNames []string) error {
	dnsNames := sets.NewString(cert.DNSNames...)
	if dnsNames.HasAll(expectedDNSNames...) {
		return nil
	}
	return ErrInvalidCertDNSNames
}
