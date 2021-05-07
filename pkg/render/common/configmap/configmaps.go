package configmap

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CopyToNamespace returns a new list of config maps generated from the ones given but with the namespace changed to the
// given one.
func CopyToNamespace(ns string, oConfigMaps ...*v1.ConfigMap) []*v1.ConfigMap {
	var configMaps []*v1.ConfigMap
	for _, s := range oConfigMaps {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		configMaps = append(configMaps, x)
	}
	return configMaps
}

// ToRuntimeObjects converts the given list of configMaps to a list of client.Objects
func ToRuntimeObjects(configMaps ...*v1.ConfigMap) []client.Object {
	var objs []client.Object
	for _, secret := range configMaps {
		if secret == nil {
			continue
		}
		objs = append(objs, secret)
	}
	return objs
}
