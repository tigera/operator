package certificatemanagement

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	CASecretName                = "tigera-ca-private"
	TrustedCertConfigMapName    = "tigera-ca-bundle"
	TrustedCertConfigMapKeyName = "tigera-ca-bundle.crt"
	TrustedCertVolumeMountPath  = "/etc/pki/tls/certs/"
	TrustedCertBundleMountPath  = "/etc/pki/tls/certs/tigera-ca-bundle.crt"
)

// KeyPairInterface wraps a Secret object that contains a private key and a certificate. Whether CertificateManagement is
// configured or not, KeyPair returns the right InitContainer, VolumeMount or Volume (when applicable).
type KeyPairInterface interface {
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
	CertificateInterface
}

// Certificate wraps the certificate. Combine this with a TrustedBundle, to mount a trusted certificate bundle to a pod.
type CertificateInterface interface {
	GetIssuer() CertificateInterface
	GetCertificatePEM() []byte
	GetName() string
}

// TrustedBundle is used to create a trusted certificate bundle of the CertificateManager CA and 0 or more Certificates.
type TrustedBundle interface {
	MountPath() string
	ConfigMap(namespace string) *corev1.ConfigMap
	HashAnnotations() map[string]string
	VolumeMount() corev1.VolumeMount
	Volume() corev1.Volume
	AddCertificates(certificates ...CertificateInterface)
}
