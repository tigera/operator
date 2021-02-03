package util

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CopySecrets(ns string, oSecrets ...*v1.Secret) []*v1.Secret {
	var secrets []*v1.Secret
	for _, s := range oSecrets {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		secrets = append(secrets, x)
	}
	return secrets
}

func CopyConfigMaps(ns string, oConfigMaps ...*v1.ConfigMap) []*v1.ConfigMap {
	var configMaps []*v1.ConfigMap
	for _, s := range oConfigMaps {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		configMaps = append(configMaps, x)
	}
	return configMaps
}
