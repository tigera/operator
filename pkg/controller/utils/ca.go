package utils

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type trustedBundle struct {
	pem         []byte
	annotations map[string]string
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
func CreateTrustedBundle(ca tls.TigeraCA, certificates ...tls.Certificate) (tls.TrustedBundle, error) {
	annotations := make(map[string]string, len(certificates))
	pem := bytes.Buffer{}
	writePem := func(cert tls.Certificate) error {
		if cert != nil {
			annotations[cert.HashAnnotationKey()] = cert.HashAnnotationValue()
			secret := cert.Secret("")
			_, err := pem.WriteString(fmt.Sprintf("# secret: %s\n%s\n\n", secret.Name, string(secret.Data[corev1.TLSCertKey])))
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := writePem(ca); err != nil {
		return nil, err
	}
	for _, cert := range certificates {
		if cert != nil && cert.X509Certificate() != nil && !ca.Issued(cert) {
			err := writePem(cert)
			if err != nil {
				return nil, err
			}
		}
	}
	return &trustedBundle{pem: pem.Bytes(), annotations: annotations}, nil
}

func (t *trustedBundle) MountPath() string {
	return tls.TrustedCertBundleMountPath
}

func (t *trustedBundle) HashAnnotations() map[string]string {
	return t.annotations
}

func (t *trustedBundle) VolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      tls.TrustedCertConfigMapName,
		MountPath: tls.TrustedCertVolumeMountPath,
		ReadOnly:  true,
	}
}

func (t *trustedBundle) Volume() corev1.Volume {
	return corev1.Volume{
		Name: tls.TrustedCertConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: tls.TrustedCertConfigMapName},
			},
		},
	}
}

func (t *trustedBundle) ConfigMap(namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      tls.TrustedCertConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			tls.TrustedCertConfigMapKeyName: string(t.pem),
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

type tigeraCA struct {
	*crypto.CA
	keyPair
}

// CreateTigeraCA creates a signer of new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, TigeraCA will preserve and return them.
func CreateTigeraCA(cli client.Client, certificateManagement *operatorv1.CertificateManagement, clusterDomain string) (tls.TigeraCA, error) {
	var cryptoCA *crypto.CA
	var caSecret *corev1.Secret
	if certificateManagement != nil {
		caSecret = &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      tls.TigeraCASecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				corev1.TLSCertKey: certificateManagement.CACert,
			},
		}
	} else {
		caSecret = &corev1.Secret{}
		err := cli.Get(context.Background(), types.NamespacedName{
			Name:      tls.TigeraCASecretName,
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
			caSecret, err = getSecretFromTLSConfig(cryptoCA.Config, tls.TigeraCASecretName, common.OperatorNamespace())
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
	return &tigeraCA{
		CA: cryptoCA,
		keyPair: keyPair{
			Certificate:           x509Cert,
			secret:                caSecret,
			clusterDomain:         clusterDomain,
			CertificateManagement: certificateManagement,
		},
	}, nil
}

// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
func (ca *tigeraCA) GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (tls.KeyPair, error) {
	secret := &corev1.Secret{}
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
	}
	kp := &keyPair{
		tigeraCA: ca,
		dnsNames: dnsNames,
	}

	if !createNew {
		err = standardizeFields(secret)
		if err != nil {
			return nil, err
		}
		err = SecretHasExpectedDNSNames(secret, corev1.TLSCertKey, dnsNames)
		if err == ErrInvalidCertDNSNames {
			return nil, fmt.Errorf("secret %s has invalid DNS names, the expected names are: %v", secretName, dnsNames)
		} else if err != nil {
			return nil, err
		}
		kp.Certificate, err = parseCertificate(secret.Data[corev1.TLSCertKey])
		if err != nil {
			return nil, err
		}
		invalid := kp.Certificate.NotAfter.Before(time.Now()) || kp.Certificate.NotBefore.After(time.Now())

		if invalid && !strings.HasPrefix(kp.Certificate.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) {
			return nil, fmt.Errorf("secret %s is invalid", secretName)
		}
		// Create a new secret if the secret has invalid or has been signed by an older instance of TigeraCA.
		createNew = invalid || kp.Certificate.Issuer.CommonName == rmeta.TigeraOperatorCAIssuerPrefix && !ca.Issued(kp)
	} else {
		if ca.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(ca, secretName, secretNamespace, dnsNames), nil
		}
		tlsCfg, err := ca.MakeServerCertForDuration(sets.NewString(dnsNames...), rmeta.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
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

// Issued returns true if the provided certificate was signed by TigeraCA and returns false for user provided KeyPairs or Certificate Management.
func (ca *tigeraCA) Issued(cert tls.Certificate) bool {
	return ca.CertificateManagement() == nil && cert != nil &&
		string(cert.X509Certificate().AuthorityKeyId) == string((ca.X509Certificate()).AuthorityKeyId)
}

// GetCertificate returns a Certificate. If the certificate is not found a k8s.io NotFound error is returned.
func (ca *tigeraCA) GetCertificate(cli client.Client, secretName, secretNamespace string) (tls.Certificate, error) {
	if ca.CertificateManagement() != nil {
		return certificateManagementKeyPair(ca, secretName, secretNamespace, nil), nil
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
	return &keyPair{tigeraCA: ca, Certificate: x509Cert, secret: secret}, nil
}

// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, a k8s.io NotFound error is returned.
func (ca *tigeraCA) GetKeyPair(cli client.Client, secretName, secretNamespace string) (tls.KeyPair, error) {
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		if !kerrors.IsNotFound(err) && ca.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(ca, secretName, secretNamespace, nil), nil
		}
		return nil, err
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
		tigeraCA:    ca,
		secret:      secret,
		Certificate: certificate,
	}, nil
}

// CertificateManagement returns the CertificateManagement object or nil if it is not configured.
func (ca *tigeraCA) CertificateManagement() *operatorv1.CertificateManagement {
	return ca.keyPair.CertificateManagement
}

type keyPair struct {
	*x509.Certificate
	secret        *corev1.Secret
	clusterDomain string
	*operatorv1.CertificateManagement
	dnsNames                 []string
	useCertificateManagement bool
	tigeraCA                 tls.TigeraCA
}

// UseCertificateManagement is true if this secret is not BYO and certificate management is used to provide the a pair to a pod.
func (c *keyPair) UseCertificateManagement() bool {
	return c.useCertificateManagement
}

// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
func (c *keyPair) BYO() bool {
	return c.useCertificateManagement == false && !c.tigeraCA.Issued(c)
}

func (c *keyPair) X509Certificate() *x509.Certificate {
	return c.Certificate
}

// certificateManagementKeyPair returns a KeyPair for to be used when certificate management is used to provide a key pair to a pod.
func certificateManagementKeyPair(ca *tigeraCA, secretName, secretNamespace string, dnsNames []string) *keyPair {
	return &keyPair{
		secret: &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: secretNamespace}},
		Certificate:              ca.Certificate,
		CertificateManagement:    ca.CertificateManagement(),
		useCertificateManagement: true,
		dnsNames:                 dnsNames,
		tigeraCA:                 ca,
	}
}

// NewKeyPair returns  a KeyPair, which wraps a Secret object that contains a private key and a certificate. Whether certificate
// management is configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
func NewKeyPair(tigeraCA tls.TigeraCA, secret *corev1.Secret, dnsNames []string, clusterDomain string) (tls.KeyPair, error) {
	certificate, err := parseCertificate(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}
	return &keyPair{
		secret:        secret,
		dnsNames:      dnsNames,
		clusterDomain: clusterDomain,
		Certificate:   certificate,
		tigeraCA:      tigeraCA,
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
	return (*c.Certificate.SerialNumber).String()
}

func (c *keyPair) Volume() corev1.Volume {
	volumeSource := render.CertificateVolumeSource(c.CertificateManagement, c.secret.Name)
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
	initContainer := render.CreateCSRInitContainer(
		c.CertificateManagement,
		csrImage,
		c.secret.Name,
		c.dnsNames[0],
		corev1.TLSPrivateKeyKey,
		corev1.TLSCertKey,
		c.dnsNames,
		namespace)
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

// NewKeyPairPassthrough is a convenience func for constructing a passthrough to create or clean up secrets in the operator namespace.
func NewKeyPairPassthrough(keyPair tls.KeyPair) render.Component {
	if keyPair.UseCertificateManagement() {
		return render.NewDeletionPassthrough(keyPair.Secret(common.OperatorNamespace()))
	}
	return render.NewPassthrough(keyPair.Secret(common.OperatorNamespace()))
}
