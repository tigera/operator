package data

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CopyConfigMaps returns a new list of config maps generated from the ones given but with the namespace changed to the
// given one.
func CopyConfigMaps(ns string, oConfigMaps ...*v1.ConfigMap) []*v1.ConfigMap {
	var configMaps []*v1.ConfigMap
	for _, s := range oConfigMaps {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		configMaps = append(configMaps, x)
	}
	return configMaps
}
