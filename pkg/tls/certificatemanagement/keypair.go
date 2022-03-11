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

var (
	ErrInvalidCertNoPEMData = errors.New("cert has no PEM data")
)

type KeyPair struct {
	CSRImage       string
	Name           string
	PrivateKeyPEM  []byte
	CertificatePEM []byte
	ClusterDomain  string
	*operatorv1.CertificateManagement
	DNSNames []string
	Issuer   KeyPairInterface
}

func (k *KeyPair) GetCertificatePEM() []byte {
	return k.CertificatePEM
}

func (k *KeyPair) GetName() string {
	return k.Name
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
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: k.GetName(), Namespace: namespace},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: k.PrivateKeyPEM,
			corev1.TLSCertKey:       k.CertificatePEM,
		},
	}
}

func (k *KeyPair) HashAnnotationKey() string {
	return fmt.Sprintf("hash.operator.tigera.io/%s", k.GetName())
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

// NewKeyPair returns a KeyPair, which wraps a Secret object that contains a private key and a certificate. Whether certificate
// management is configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
func NewKeyPair(secret *corev1.Secret, dnsNames []string, clusterDomain string) (KeyPairInterface, error) {
	return &KeyPair{
		Name:           secret.Name,
		PrivateKeyPEM:  secret.Data[corev1.TLSPrivateKeyKey],
		CertificatePEM: secret.Data[corev1.TLSCertKey],
		DNSNames:       dnsNames,
		ClusterDomain:  clusterDomain,
	}, nil
}
