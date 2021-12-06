package utils

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/openshift/library-go/pkg/crypto"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	TigeraCASecretName    = "tigera-ca-private"
	TigeraCAConfigMapName = "tigera-ca-public"
	DefaultCertMount      = "/etc/pki/tls/certs/tigera-ca.crt"
)

type TigeraCA interface {
	GetOrCreateCertificate(cli client.Client, cn, secretName, secretNamespace string, dnsNames []string) (Certificate, error)
	Certificate
}

type Certificate interface {
	Secret() *corev1.Secret
	HashAnnotation() (string, string)
	VolumeMount() corev1.VolumeMount
}

type tigeraCA struct {
	certificateManagement *operatorv1.CertificateManagement
	*crypto.CA
	certificate
}

type certificate struct {
	*x509.Certificate
	certPem       []byte
	name          string
	secret        *corev1.Secret
	clusterDomain string
	issuer        string
}

func CreateTigeraCA(cli client.Client, certificateManagement *operatorv1.CertificateManagement, clusterDomain string) (TigeraCA, error) {
	if certificateManagement != nil {
		return &tigeraCA{
			certificateManagement: certificateManagement,
		}, nil
	}

	var cryptoCA *crypto.CA
	caSecret, err := ValidateCertPair(cli, common.OperatorNamespace(), TigeraCASecretName, corev1.TLSPrivateKeyKey, corev1.TLSCertKey)
	if err != nil {
		return nil, err
	}
	if caSecret == nil ||
		len(caSecret.Data) == 0 ||
		len(caSecret.Data[corev1.TLSPrivateKeyKey]) == 0 ||
		len(caSecret.Data[corev1.TLSCertKey]) == 0 {
		// create a new CA
		cryptoCA, err = tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix)
		if err != nil {
			return nil, err
		}
		caSecret, err = getSecretFromTLSConfig(cryptoCA.Config, TigeraCASecretName, common.OperatorNamespace())
		if err != nil {
			return nil, err
		}
	} else {
		cryptoCA, err = crypto.GetCAFromBytes(caSecret.Data[corev1.TLSCertKey], caSecret.Data[corev1.TLSPrivateKeyKey])
	}
	x509Cert, err := parseCertificate(caSecret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, err
	}
	return &tigeraCA{
		CA: cryptoCA,
		certificate: certificate{
			Certificate:   x509Cert,
			name:          rmeta.TigeraOperatorCAIssuerPrefix,
			secret:        caSecret,
			clusterDomain: clusterDomain,
			issuer:        rmeta.TigeraOperatorCAIssuerPrefix,
		},
	}, nil
}

func (ca *tigeraCA) GetOrCreateCertificate(cli client.Client, cn, secretName, secretNamespace string, dnsNames []string) (Certificate, error) {
	secret, err := ValidateCertPair(cli, secretNamespace, secretName, corev1.TLSPrivateKeyKey, corev1.TLSCertKey)
	if err != nil {
		return nil, err
	}
	var x509Cert *x509.Certificate
	createNew := secret == nil
	if !createNew {
		err = SecretHasExpectedDNSNames(secret, cn, dnsNames)
		if err == ErrInvalidCertDNSNames {
			createNew = true
		} else if err != nil {
			return nil, err
		}
		x509Cert, err = parseCertificate(secret.Data[corev1.TLSCertKey])
		if err != nil {
			return nil, err
		}
		// If issued by the operator, check if it was signed by this ca cert.
		createNew = IsOperatorIssued(x509Cert.Issuer.CommonName) && x509Cert.Issuer.SerialNumber != (*ca.SerialNumber).String()
	}
	if createNew {
		cert, err := ca.MakeServerCertForDuration(sets.NewString(dnsNames...), rmeta.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
		if err != nil {
			return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
		}
		secret, err = getSecretFromTLSConfig(cert, cn, secretNamespace)
		if err != nil {
			return nil, fmt.Errorf("unable to create secret: %s", err)
		}
	}

	return &certificate{Certificate: x509Cert, name: cn, secret: secret}, nil
}

func (ca *certificate) ConfigMap(namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraCAConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			corev1.ServiceAccountRootCAKey: string(ca.secret.Data[corev1.TLSCertKey]),
		},
	}
}

func (c *certificate) Secret() *corev1.Secret {
	return c.secret
}

func (c *certificate) HashAnnotation() (string, string) {
	return fmt.Sprintf("hash.operator.tigera.io/%s", c.name), fmt.Sprintf("%v", *c.Certificate.SerialNumber)
}

func (c *certificate) Volume() corev1.Volume {
	return corev1.Volume{
		Name: TigeraCAConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: TigeraCAConfigMapName},
			},
		},
	}
}

func (c *certificate) VolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      TigeraCAConfigMapName,
		MountPath: DefaultCertMount,
		ReadOnly:  true,
	}
}

func getSecretFromTLSConfig(
	tls *crypto.TLSCertificateConfig, secretName, secretNamespace string) (*corev1.Secret, error) {
	keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
	if err := tls.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	data := make(map[string][]byte)
	data[corev1.TLSPrivateKeyKey] = keyContent.Bytes()
	data[corev1.TLSCertKey] = crtContent.Bytes()
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
		Data: data,
	}, nil
}
