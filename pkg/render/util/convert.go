package util

import (
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func SecretsToRuntimeObjects(secrets ...*v1.Secret) []client.Object {
	objs := make([]client.Object, len(secrets))
	for i, secret := range secrets {
		objs[i] = secret
	}
	return objs
}
