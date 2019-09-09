// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package render

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/openshift/library-go/pkg/crypto"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

const (
	Optional = true
)

var log = logf.Log.WithName("render")

func SetTestLogger(l logr.Logger) {
	log = l
}

// setCustomVolumeMounts merges a custom list of volume mounts into a default list. A custom volume mount
// overrides a default volume mount if they have the same name.
func setCustomVolumeMounts(defaults []v1.VolumeMount, custom []v1.VolumeMount) []v1.VolumeMount {
	for _, c := range custom {
		var found bool
		for i, d := range defaults {
			if c.Name == d.Name {
				defaults[i] = c
				found = true
				break
			}
		}
		if !found {
			defaults = append(defaults, c)
		}
	}
	return defaults
}

// setCustomVolumes merges a custom list of volumes into a default list. A custom volume overrides a default volume
// if they have the same name.
func setCustomVolumes(defaults []v1.Volume, custom []v1.Volume) []v1.Volume {
	for _, c := range custom {
		var found bool
		for i, d := range defaults {
			if c.Name == d.Name {
				defaults[i] = c
				found = true
				break
			}
		}
		if !found {
			defaults = append(defaults, c)
		}
	}
	return defaults
}

// setCustomTolerations merges a custom list of tolerations into a default list. A custom toleration overrides
// a default toleration only if the custom toleration operator is "Equals" and both tolerations have the same
// key and value.
func setCustomTolerations(defaults []v1.Toleration, custom []v1.Toleration) []v1.Toleration {
	for _, c := range custom {
		var found bool
		for i, d := range defaults {
			// Only override existing toleration if this is an equals operator.
			if c.Operator == v1.TolerationOpEqual && c.Key == d.Key && c.Value == d.Value {
				defaults[i] = c
				found = true
				break
			}
		}
		if !found {
			defaults = append(defaults, c)
		}
	}
	return defaults
}

// setCustomEnv merges a custom list of envvars into a default list. A custom envvar overrides a default envvar if
// they have the same name.
func setCustomEnv(defaults []v1.EnvVar, custom []v1.EnvVar) []v1.EnvVar {
	for _, c := range custom {
		var found bool
		for i, d := range defaults {
			if c.Name == d.Name {
				defaults[i] = c
				found = true
				break
			}
		}
		if !found {
			defaults = append(defaults, c)
		}
	}
	return defaults
}

func setCriticalPod(t *v1.PodTemplateSpec) {
	t.Spec.PriorityClassName = priorityClassName
}

// envVarSourceFromConfigmap returns an EnvVarSource using the given configmap name and configmap key.
func envVarSourceFromConfigmap(configmapName, key string) *v1.EnvVarSource {
	return &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: configmapName,
			},
			Key: key,
		},
	}
}

// envVarSourceFromSecret returns an EnvVarSource using the given secret name and key.
func envVarSourceFromSecret(secretName, key string, optional bool) *v1.EnvVarSource {
	var opt *bool
	if optional {
		real := optional
		opt = &real
	}
	return &v1.EnvVarSource{
		SecretKeyRef: &v1.SecretKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: secretName,
			},
			Key:      key,
			Optional: opt,
		},
	}
}

// TODO: Once this is not used in any renderers remove it from here.
// validateCertPair checks if the given secret exists and if so
// that it contains key and cert fields. If a secret exists then it is returned.
// If there is an error accessing the secret (except NotFound) or the cert
// does not have both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no cert is valid.
func validateCertPair(client client.Client, certPairSecretName, keyName, certName string) (*v1.Secret, error) {
	secret := &v1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: certPairSecretName, Namespace: OperatorNamespace()}
	err := client.Get(context.Background(), secretNamespacedName, secret)
	if err != nil {
		// If the reason for the error is not found then that is acceptable
		// so return valid in that case.
		statErr, ok := err.(*kerrors.StatusError)
		if ok && statErr.ErrStatus.Reason == metav1.StatusReasonNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("Failed to read cert %q from datastore: %s", certPairSecretName, err)
		}
	}

	if val, ok := secret.Data[keyName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("Secret %q does not have a field named %q", certPairSecretName, keyName)
	}
	if val, ok := secret.Data[certName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("Secret %q does not have a field named %q", certPairSecretName, certName)
	}

	return secret, nil
}

func makeCA() (*crypto.CA, error) {
	temporaryCertDir, err := ioutil.TempDir("", "serving-cert-")
	if err != nil {
		return nil, err
	}
	signerName := fmt.Sprintf("%s-signer@%d", "tigera-operator", time.Now().Unix())
	return crypto.MakeSelfSignedCA(
		filepath.Join(temporaryCertDir, "serving-signer.crt"),
		filepath.Join(temporaryCertDir, "serving-signer.key"),
		filepath.Join(temporaryCertDir, "serving-signer.serial"),
		signerName,
		0,
	)
}

// makeSignedCertKeyPair generates and returns a key pair for a self signed cert. The first hostname provided is used
// as the common name for the certificate. If hostnames are not provided, localhost is used.
// This code came from:
// https://github.com/openshift/library-go/blob/84f02c4b7d6ab9d67f63b13586693600051de401/pkg/controller/controllercmd/cmd.go#L153
func makeSignedTLSPair(ca *crypto.CA, fns []crypto.CertificateExtensionFunc, hostnames ...string) (tls *crypto.TLSCertificateConfig, err error) {
	if ca == nil {
		ca, err = makeCA()
		if err != nil {
			return nil, err
		}
	}

	// localhost is the default hostname for the generated certificate if none are provided.
	hostnamesSet := sets.NewString("localhost")
	if len(hostnames) > 0 {
		hostnamesSet = sets.NewString(hostnames...)
	}
	// Set cert expiration to 100 years
	return ca.MakeServerCert(hostnamesSet, 100*365, fns...)
}

//type CertificateExtensionFunc func(*x509.Certificate) error
func setClientAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	return nil
}
func setServerAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	return nil
}

// createOperatorTLSSecret Creates a new TLS secret with the information passed
//   ca: The ca to use for creating the Cert/Key pair. If nil then a
//       self-signed CA will be created
//   secretName: The name of the secret.
//   secretKeyName: The name of the data field that will contain the key.
//   secretCertName: The name of the data field that will contain the cert.
//   hostnames: The first will be used as the CN, and the rest as SANs. If
//     no hostnames are provided then "localhost" will be used.
func createOperatorTLSSecret(
	ca *crypto.CA,
	secretName string,
	secretKeyName string,
	secretCertName string,
	cef []crypto.CertificateExtensionFunc,
	hostnames ...string,
) (*v1.Secret, error) {
	log.Info("Creating certificate secret", "secret", secretName)
	// Create cert
	cert, err := makeSignedTLSPair(ca, cef, hostnames...)
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

// ParseEndpoint parses an endpoint of the form scheme://host:port and returns the components.
func ParseEndpoint(endpoint string) (string, string, string, error) {
	url, err := url.Parse(endpoint)
	if err != nil {
		return "", "", "", err
	}
	splits := strings.Split(url.Host, ":")
	if len(splits) != 2 {
		return "", "", "", fmt.Errorf("Invalid host: %s", url.Host)
	}
	return url.Scheme, splits[0], splits[1], nil
}

func copyImagePullSecrets(pullSecrets []*v1.Secret, ns string) []runtime.Object {
	secrets := []runtime.Object{}
	for _, s := range pullSecrets {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		secrets = append(secrets, x)
	}
	return secrets
}

func getImagePullSecretReferenceList(pullSecrets []*v1.Secret) []v1.LocalObjectReference {
	ps := []v1.LocalObjectReference{}
	for _, x := range pullSecrets {
		ps = append(ps, v1.LocalObjectReference{Name: x.Name})
	}
	return ps
}

func OperatorNamespace() string {
	v, ok := os.LookupEnv("OPERATOR_NAMESPACE")
	if ok {
		return v
	}
	return "tigera-operator"
}
