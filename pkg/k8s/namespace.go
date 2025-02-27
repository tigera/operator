package k8s

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Namespace struct {
	ns corev1.Namespace
}

func (n Namespace) Objects() []client.Object {
	return []client.Object{&n.ns}
}
