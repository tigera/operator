package render

import (
	"os"

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
	ns := []runtime.Object{
		createNamespace(calicoNamespace),
	}

	if cr.Spec.Variant == operatorv1alpha1.TigeraSecureEnterprise {
		ns = append(ns, createNamespace(tigeraSecureNamespace))
	}
	return ns
}

func createNamespace(name string) *v1.Namespace {
	ns := &v1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{"name": name},
			Annotations: map[string]string{},
		},
	}

	// OpenShift requires special labels and annotations.
	if os.Getenv("OPENSHIFT") == "true" {
		ns.Labels["openshift.io/run-level"] = "0"
		ns.Annotations["openshift.io/node-selector"] = ""
	}
	return ns
}
