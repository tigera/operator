package render

import (
	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	calicoNamespace       = "calico-system"
	tigeraSecureNamespace = "tigera-system"
)

func Namespaces(cr *operatorv1alpha1.Core) []runtime.Object {
	return []runtime.Object{
		calicoComponentsNamespace(cr),
	}
}

func calicoComponentsNamespace(cr *operatorv1alpha1.Core) *v1.Namespace {
	return &v1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: calicoNamespace,
		},
	}
}
