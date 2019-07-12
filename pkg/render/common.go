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
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("render")

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

func verifyComponentDependenciesReady(component Component, client client.Client) bool {
	for _, obj := range component.GetComponentDeps() {
		objMeta := obj.(metav1.ObjectMetaAccessor).GetObjectMeta()
		objName := objMeta.GetName()
		objNamespace := objMeta.GetNamespace()

		switch obj.(type) {
		case *v1.Service:
			if ready := verifyServiceReady(client, objName, objNamespace); !ready {
				return false
			}
		}
	}
	return true
}

func verifyServiceReady(client client.Client, name, namespace string) bool {
	logger := log.WithName("verify_service_ready")
	service := &v1.Service{}
	svcName := types.NamespacedName{Name: name, Namespace: namespace}
	err := client.Get(context.Background(), svcName, service)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Service dependency doesn't exist yet", "name", name, "namespace", namespace)
		} else {
			logger.Info("Error getting service", "name", name, "namespace", namespace, "error", err.Error())
		}
		return false
	}

	// If the service exists, check that its ready by looking for at least 1 ready address in all of its
	// endpoints' subsets.
	err = wait.PollImmediate(3*time.Second, 30*time.Second, func() (bool, error) {
		endpoints := &v1.Endpoints{}
		err = client.Get(context.Background(), svcName, endpoints)
		if err != nil {
			// If not found, retry.
			if apierrors.IsNotFound(err) {
				logger.Info("Endpoints dependency doesn't exist yet", "name", name, "namespace", namespace)
				return false, nil
			}

			// Any other error, just quit
			return false, err
		}

		for _, subset := range endpoints.Subsets {
			if len(subset.Addresses) == 0 {
				logger.Info("Endpoints dependency has 0 ready addresses", "name", name, "namespace", namespace)
				return false, nil
			}
		}
		// If we reach here, all of the endpoints subsets have at least 1 ready address and the service is ready
		logger.Info("Service dependency is ready", "name", name, "namespace", namespace)
		return true, nil
	})

	if err != nil {
		logger.Info("Service dependency check failed", "error", err.Error())
		return false
	}

	return true
}
