package util

import (
	"bytes"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

func MakeCA() (*crypto.CA, error) {
	signerName := fmt.Sprintf("%s@%d", TigeraOperatorCAIssuerPrefix, time.Now().Unix())

	caConfig, err := crypto.MakeSelfSignedCAConfigForDuration(
		signerName,
		100*365*24*time.Hour, //100years*365days*24hours
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to create CA: %s", err)
	}
	return &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          caConfig,
	}, nil
}

// makeSignedCertKeyPair generates and returns a key pair for a self signed cert. The first hostname provided is used
// as the common name for the certificate. If hostnames are not provided, localhost is used.
// This code came from:
// https://github.com/openshift/library-go/blob/84f02c4b7d6ab9d67f63b13586693600051de401/pkg/controller/controllercmd/cmd.go#L153
func makeSignedTLSPair(ca *crypto.CA, fns []crypto.CertificateExtensionFunc, dur time.Duration, hostnames ...string) (tls *crypto.TLSCertificateConfig, err error) {
	if ca == nil {
		ca, err = MakeCA()
		if err != nil {
			return nil, err
		}
	}

	// localhost is the default hostname for the generated certificate if none are provided.
	hostnamesSet := sets.NewString("localhost")
	if len(hostnames) > 0 {
		hostnamesSet = sets.NewString(hostnames...)
	}
	return ca.MakeServerCertForDuration(hostnamesSet, dur, fns...)
}

// CreateOperatorTLSSecret Creates a new TLS secret with the information passed
//   ca: The ca to use for creating the Cert/Key pair. If nil then a
//       self-signed CA will be created
//   secretName: The name of the secret.
//   secretKeyName: The name of the data field that will contain the key.
//   secretCertName: The name of the data field that will contain the cert.
//   dur: How long the certificate will be valid.
//   hostnames: The first will be used as the CN, and the rest as SANs. If
//     no hostnames are provided then "localhost" will be used.
func CreateOperatorTLSSecret(
	ca *crypto.CA,
	secretName string,
	secretKeyName string,
	secretCertName string,
	dur time.Duration,
	cef []crypto.CertificateExtensionFunc,
	hostnames ...string,
) (*v1.Secret, error) {
	log.Info("Creating certificate secret", "secret", secretName)
	// Create cert
	cert, err := makeSignedTLSPair(ca, cef, dur, hostnames...)
	if err != nil {
		log.Error(err, "Unable to create signed cert pair")
		return nil, fmt.Errorf("Unable to create signed cert pair: %s", err)
	}

	return getOperatorSecretFromTLSConfig(cert, secretName, secretKeyName, secretCertName)
}

func getOperatorSecretFromTLSConfig(
	tls *crypto.TLSCertificateConfig,
	secretName string,
	secretKeyName string,
	secretCertName string,
) (*v1.Secret, error) {

	crtContent := &bytes.Buffer{}
	keyContent := &bytes.Buffer{}
	if err := tls.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	data := make(map[string][]byte)
	data[secretKeyName] = keyContent.Bytes()
	data[secretCertName] = crtContent.Bytes()
	return &v1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: OperatorNamespace(),
		},
		Data: data,
	}, nil
}
