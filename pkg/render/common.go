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
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

// validateManagerCertPair checks if the given secret exists and if so
// that it contains key and cert fields. If a secret exists then it is returned.
// If there is an error accessing the secret (except NotFound) or the cert
// does not have both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no cert is valid.
func validateManagerCertPair(client client.Client, certPairSecretName, keyName, certName string) (*v1.Secret, error) {
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
