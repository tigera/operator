package data

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	v1 "k8s.io/api/core/v1"
)

// GetImagePullSecretReferenceList retrieves the object references from the pull secrets and returns that list.
func GetImagePullSecretReferenceList(pullSecrets []*v1.Secret) []v1.LocalObjectReference {
	var ps []v1.LocalObjectReference
	for _, x := range pullSecrets {
		ps = append(ps, v1.LocalObjectReference{Name: x.Name})
	}
	return ps
}

// GetResourceRequirements retrieves the component ResourcesRequirements from the installation. If it doesn't exist, it
// returns an empty ResourceRequirements struct.
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

// EnvVarSourceFromSecret returns an EnvVarSource using the given secret name and key.
func EnvVarSourceFromSecret(secretName, key string, optional bool) *v1.EnvVarSource {
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
