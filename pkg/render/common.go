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
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/openshift/library-go/pkg/crypto"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
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

// validateCertPair checks if the given secret exists and if so
// that it contains key and cert fields. If a secret exists then it is returned.
// If there is an error accessing the secret (except NotFound) or the cert
// does not have both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no cert is valid.
func validateCertPair(client client.Client, certPairSecretName, keyName, certName string) (*v1.Secret, error) {
	secret := &v1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: certPairSecretName, Namespace: operatorNamespace}
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

// makeSignedCertKeyPair generates and returns a key pair for a self signed cert. The first hostname provided is used
// as the common name for the certificate. If hostnames are not provided, localhost is used.
// This code came from:
// https://github.com/openshift/library-go/blob/84f02c4b7d6ab9d67f63b13586693600051de401/pkg/controller/controllercmd/cmd.go#L153
func makeSignedCertKeyPair(hostnames ...string) (key, cert []byte, err error) {
	temporaryCertDir, err := ioutil.TempDir("", "serving-cert-")
	if err != nil {
		return nil, nil, err
	}
	signerName := fmt.Sprintf("%s-signer@%d", "tigera-operator", time.Now().Unix())
	ca, err := crypto.MakeSelfSignedCA(
		filepath.Join(temporaryCertDir, "serving-signer.crt"),
		filepath.Join(temporaryCertDir, "serving-signer.key"),
		filepath.Join(temporaryCertDir, "serving-signer.serial"),
		signerName,
		0,
	)
	if err != nil {
		return nil, nil, err
	}

	// localhost is the default hostname for the generated certificate if none are provided.
	hostnamesSet := sets.NewString("localhost")
	if len(hostnames) > 0 {
		hostnamesSet = sets.NewString(hostnames...)
	}
	// TODO: allow cert expiry configuration
	servingCert, err := ca.MakeServerCert(hostnamesSet, 30)
	if err != nil {
		return nil, nil, err
	}
	crtContent := &bytes.Buffer{}
	keyContent := &bytes.Buffer{}
	if err := servingCert.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, nil, err
	}

	return keyContent.Bytes(), crtContent.Bytes(), nil
}

// createTLSSecret if the key (kk) or cert (cc) passed in are empty
// then a new cert/key pair is created, they are returned as key/cert and a
// secret is returned populated with the key/cert.
// If k,c are populated then this indicates the secret already exists in the tigera-operator
// namespace so no new key/cert is created and no Secret is returned,
// but the passed in k,c values are returned as key,cert.
// hostnames are used in the cert generation, with the first hostname used as the CN. If none are provided,
// then localhost is used.
func createTLSSecret(kk, cc []byte, secretName, secretKeyName, secretCertName string, hostnames ...string) (key, cert []byte, s *v1.Secret) {
	if len(kk) != 0 && len(cc) != 0 {
		// If the secret already exists in the tigera-operator NS then nothing to do,
		// so no need to return it to be created.
		return kk, cc, nil
	}

	log.Info("Creating self-signed certificate", "secret", secretName)
	// Create cert
	var err error
	key, cert, err = makeSignedCertKeyPair()
	if err != nil {
		log.Error(err, "Unable to create signed cert pair")
		return nil, nil, nil
	}

	data := make(map[string][]byte)
	data[secretKeyName] = key
	data[secretCertName] = cert
	return key, cert, &v1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: operatorNamespace,
		},
		Data: data,
	}
}
