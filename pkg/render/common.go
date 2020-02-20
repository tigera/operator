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
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

const (
	Optional                   = true
	DefaultCertificateDuration = 100 * 365 * 24 * time.Hour
)

var log = logf.Log.WithName("render")

func SetTestLogger(l logr.Logger) {
	log = l
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

func makeCA() (*crypto.CA, error) {
	signerName := fmt.Sprintf("%s-signer@%d", "tigera-operator", time.Now().Unix())

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
	return ca.MakeServerCertForDuration(hostnamesSet, dur, fns...)
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

func ParseHostPort(hostport string) (string, string, error) {
	splits := strings.Split(hostport, ":")
	if len(splits) != 2 {
		return "", "", fmt.Errorf("Invalid HostPort: %s", hostport)
	}
	return splits[0], splits[1], nil

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

func CopySecrets(ns string, oSecrets ...*v1.Secret) []*v1.Secret {
	var secrets []*v1.Secret
	for _, s := range oSecrets {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		secrets = append(secrets, x)
	}
	return secrets
}

func copyConfigMaps(ns string, oConfigMaps ...*v1.ConfigMap) []runtime.Object {
	var configMaps []runtime.Object
	for _, s := range oConfigMaps {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		configMaps = append(configMaps, x)
	}
	return configMaps
}

func getImagePullSecretReferenceList(pullSecrets []*v1.Secret) []v1.LocalObjectReference {
	ps := []v1.LocalObjectReference{}
	for _, x := range pullSecrets {
		ps = append(ps, v1.LocalObjectReference{Name: x.Name})
	}
	return ps
}

// AnnotationHash is to generate a hash that can be included in a Deployment
// or DaemonSet to trigger a restart/rolling update when a ConfigMap or Secret
// is updated.
func AnnotationHash(i interface{}) string {
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%q", i)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// secretsAnnotationHash generates a hash based off of the data in each secrets Data field that can be used by Deployments
// or DaemonSets to trigger a restart/rolling update based on changes to one of more secrets data
func secretsAnnotationHash(secrets ...*corev1.Secret) string {
	var annoteArr []map[string][]byte
	for _, secret := range secrets {
		annoteArr = append(annoteArr, secret.Data)
	}

	return AnnotationHash(annoteArr)
}

func OperatorNamespace() string {
	v, ok := os.LookupEnv("OPERATOR_NAMESPACE")
	if ok {
		return v
	}
	return "tigera-operator"
}

func securityContext() *v1.SecurityContext {
	runAsNonRoot := true
	allowPriviledgeEscalation := false
	return &v1.SecurityContext{
		RunAsNonRoot:             &runAsNonRoot,
		AllowPrivilegeEscalation: &allowPriviledgeEscalation,
	}
}

func secretsToRuntimeObjects(secrets ...*v1.Secret) []runtime.Object {
	objs := make([]runtime.Object, len(secrets))
	for i, secret := range secrets {
		objs[i] = secret
	}
	return objs
}
