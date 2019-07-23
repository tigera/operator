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
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
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
func envVarSourceFromSecret(secretName, key string) *v1.EnvVarSource {
	return &v1.EnvVarSource{
		SecretKeyRef: &v1.SecretKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: secretName,
			},
			Key: key,
		},
	}
}
