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
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
)

const (
	Optional                   = true
	DefaultCertificateDuration = 100 * 365 * 24 * time.Hour

	OSTypeAny     OSType = "any"
	OSTypeLinux   OSType = "linux"
	OSTypeWindows OSType = "windows"

	// The name prefix used for the CA issuer, which is used for self-signed
	// certificates issued for operator-managed certificates.
	// NOTE: Do not change this field since we use this value to identify
	// certificates managed by this operator.
	TigeraOperatorCAIssuerPrefix = "tigera-operator-signer"
)

// This type helps ensure that we only use defined os types
type OSType string

var log = logf.Log.WithName("render")

func SetTestLogger(l logr.Logger) {
	log = l
}

func setCriticalPod(t *v1.PodTemplateSpec) {
	t.Spec.PriorityClassName = PriorityClassName
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

func copyImagePullSecrets(pullSecrets []*v1.Secret, ns string) []client.Object {
	secrets := []client.Object{}
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

func copyConfigMaps(ns string, oConfigMaps ...*v1.ConfigMap) []*v1.ConfigMap {
	var configMaps []*v1.ConfigMap
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

// GetResourceRequirements retrieves the component ResourcesRequirements from the installation
// If it doesn't exist, it returns an empty ResourceRequirements struct
func GetResourceRequirements(i *operatorv1.InstallationSpec, name operatorv1.ComponentName) v1.ResourceRequirements {
	if i.ComponentResources != nil {
		for _, cr := range i.ComponentResources {
			if cr.ComponentName == name && cr.ResourceRequirements != nil {
				return *cr.ResourceRequirements
			}
		}
	}
	return v1.ResourceRequirements{}
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
	return &v1.SecurityContext{
		RunAsNonRoot:             Bool(true),
		AllowPrivilegeEscalation: Bool(false),
	}
}

func secretsToRuntimeObjects(secrets ...*v1.Secret) []client.Object {
	objs := make([]client.Object, len(secrets))
	for i, secret := range secrets {
		objs[i] = secret
	}
	return objs
}

// Creates the base pod security policy with the minimal required permissions to be overridden if necessary.
func basePodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	falseBool := false
	ptrBoolFalse := &falseBool
	return &policyv1beta1.PodSecurityPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"seccomp.security.alpha.kubernetes.io/allowedProfileNames": "*",
			},
		},
		Spec: policyv1beta1.PodSecurityPolicySpec{
			Privileged:               false,
			AllowPrivilegeEscalation: ptrBoolFalse,
			RequiredDropCapabilities: []v1.Capability{
				v1.Capability("ALL"),
			},
			Volumes: []policyv1beta1.FSType{
				policyv1beta1.ConfigMap,
				policyv1beta1.EmptyDir,
				policyv1beta1.Projected,
				policyv1beta1.Secret,
				policyv1beta1.DownwardAPI,
				policyv1beta1.PersistentVolumeClaim,
			},
			HostNetwork: false,
			HostPorts: []policyv1beta1.HostPortRange{
				policyv1beta1.HostPortRange{
					Min: int32(0),
					Max: int32(65535),
				},
			},
			HostIPC: false,
			HostPID: false,
			RunAsUser: policyv1beta1.RunAsUserStrategyOptions{
				Rule: policyv1beta1.RunAsUserStrategyMustRunAsNonRoot,
			},
			SELinux: policyv1beta1.SELinuxStrategyOptions{
				Rule: policyv1beta1.SELinuxStrategyRunAsAny,
			},
			SupplementalGroups: policyv1beta1.SupplementalGroupsStrategyOptions{
				Rule: policyv1beta1.SupplementalGroupsStrategyMustRunAs,
				Ranges: []policyv1beta1.IDRange{
					{
						Min: int64(1),
						Max: int64(65535),
					},
				},
			},
			FSGroup: policyv1beta1.FSGroupStrategyOptions{
				Rule: policyv1beta1.FSGroupStrategyMustRunAs,
				Ranges: []policyv1beta1.IDRange{
					{
						Min: int64(1),
						Max: int64(65535),
					},
				},
			},
			ReadOnlyRootFilesystem: false,
		},
	}
}

var (
	// tolerateMaster allows pod to be scheduled on master nodes
	tolerateMaster = corev1.Toleration{
		Key:    "node-role.kubernetes.io/master",
		Effect: corev1.TaintEffectNoSchedule,
	}

	// tolerateCriticalAddonsOnly allows pods to be rescheduled while the node is in "critical add-ons only" mode.
	tolerateCriticalAddonsOnly = corev1.Toleration{
		Key:      "CriticalAddonsOnly",
		Operator: corev1.TolerationOpExists,
	}
)

// tolerateAll returns tolerations to tolerate all taints. When used, it is not necessary
// to include the user's custom tolerations because we already tolerate everything.
var tolerateAll = []corev1.Toleration{
	tolerateCriticalAddonsOnly,
	{
		Effect:   corev1.TaintEffectNoSchedule,
		Operator: corev1.TolerationOpExists,
	},
	{
		Effect:   corev1.TaintEffectNoExecute,
		Operator: corev1.TolerationOpExists,
	},
}
