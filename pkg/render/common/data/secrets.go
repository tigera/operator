package data

import (
	"bytes"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apimachinery/pkg/util/sets"
)

// CreateOperatorTLSSecret Creates a new TLS secret with the information passed
//   ca: The ca to use for creating the Cert/Key pair. This is required.
//   secretName: The name of the secret.
//   secretKeyName: The name of the data field that will contain the key.
//   secretCertName: The name of the data field that will contain the cert.
//   dur: How long the certificate will be valid.
//   hostnames: The first will be used as the CN, and the rest as SANs. If
//     no hostnames are provided then "localhost" will be used.
//
// The first hostname provided is used as the common name for the certificate. If hostnames are not provided, localhost
// is used. This code came from:
// https://github.com/openshift/library-go/blob/84f02c4b7d6ab9d67f63b13586693600051de401/pkg/controller/controllercmd/cmd.go#L153
func CreateTLSSecret(
	ca *crypto.CA,
	secretName, secretNamespace, secretKeyName, secretCertName string,
	dur time.Duration,
	cef []crypto.CertificateExtensionFunc,
	hostnames ...string,
) (*v1.Secret, error) {
	// localhost is the default hostname for the generated certificate if none are provided.
	hostnamesSet := sets.NewString("localhost")
	if len(hostnames) > 0 {
		hostnamesSet = sets.NewString(hostnames...)
	}

	cert, err := ca.MakeServerCertForDuration(hostnamesSet, dur, cef...)
	if err != nil {
		return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
	}

	return getSecretFromTLSConfig(cert, secretName, secretNamespace, secretKeyName, secretCertName)
}

func getSecretFromTLSConfig(
	tls *crypto.TLSCertificateConfig, secretName, secretNamespace, secretKeyName, secretCertName string,
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
			Namespace: secretNamespace,
		},
		Data: data,
	}, nil
}

// CopySecrets returns a new list of secrets generated from the ones given but with the namespace changed to the given
// one.
func CopySecrets(ns string, oSecrets ...*v1.Secret) []*v1.Secret {
	var secrets []*v1.Secret
	for _, s := range oSecrets {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		secrets = append(secrets, x)
	}
	return secrets
}

// SecretsToRuntimeObjects converts the given list of secrets to a list of client.Objects
func SecretsToRuntimeObjects(secrets ...*v1.Secret) []client.Object {
	objs := make([]client.Object, len(secrets))
	for i, secret := range secrets {
		objs[i] = secret
	}
	return objs
}
