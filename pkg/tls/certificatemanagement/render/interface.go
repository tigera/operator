package render

import (
	"github.com/tigera/operator/pkg/controller/status"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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
	// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, nil is returned.
	GetKeyPair(cli client.Client, secretName, secretNamespace string) (KeyPair, error)
	// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
	GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (KeyPair, error)
	// GetCertificate returns a Certificate. If the certificate is not found a k8s.io NotFound error is returned.
	GetCertificate(cli client.Client, secretName, secretNamespace string) (Certificate, error)
	// Issued returns true if the provided certificate was signed by CertificateManager and returns false for user provided KeyPairs or Certificate Management.
	Issued(certificatePem []byte) bool
	// AddToStatusManager lets the status manager monitor pending CSRs if the certificate management is enabled.
	AddToStatusManager(manager status.StatusManager, namespace string)
	KeyPair
}

// KeyPair wraps a Secret object that contains a private key and a certificate. Whether CertificateManagement is
// configured or not, KeyPair returns the right InitContainer, VolumeMount or Volume (when applicable).
type KeyPair interface {
	//UseCertificateManagement returns true if this key pair was not user provided and certificate management has been configured.
	UseCertificateManagement() bool
	// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
	BYO() bool
	InitContainer(namespace string) corev1.Container
	VolumeMount() corev1.VolumeMount
	VolumeMountKeyFilePath() string
	VolumeMountCertificateFilePath() string
	Volume() corev1.Volume
	Secret(namespace string) *corev1.Secret
	HashAnnotationKey() string
	HashAnnotationValue() string
	Certificate
}

// Certificate wraps the certificate. Combine this with a TrustedBundle, to mount a trusted certificate bundle to a pod.
type Certificate interface {
	CertificatePEM() []byte
	Name() string
}

// TrustedBundle is used to create a trusted certificate bundle of the CertificateManager CA and 0 or more Certificates.
type TrustedBundle interface {
	MountPath() string
	ConfigMap(namespace string) *corev1.ConfigMap
	HashAnnotations() map[string]string
	VolumeMount() corev1.VolumeMount
	Volume() corev1.Volume
	AddCertificates(certificates ...Certificate)
}
