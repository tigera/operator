package testutil

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func ExpectK8sServiceEpEnvVars(podSpec corev1.PodSpec, host, port string) {
	for _, c := range podSpec.Containers {
		ExpectWithOffset(1, c.Env).To(ContainElements(
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: host},
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: port},
		), fmt.Sprintf("Container %s did not have KUBERENETES_SERVICE_... env vars", c.Name))
	}
	for _, c := range podSpec.InitContainers {
		ExpectWithOffset(1, c.Env).To(ContainElements(
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: host},
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: port},
		), fmt.Sprintf("Init container %s did not have KUBERENETES_SERVICE_... env vars", c.Name))
	}
}

func ExpectResource(resource runtime.Object, name, ns, group, version, kind string) {
	gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
	actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()
	Expect(actualName).To(Equal(name), fmt.Sprintf("Rendered %s resource in namespace %s has wrong name", kind, ns))
	Expect(actualNS).To(Equal(ns), fmt.Sprintf("Rendered resource %s/%s has wrong namespace", kind, name))
	Expect(resource.GetObjectKind().GroupVersionKind()).To(Equal(gvk), fmt.Sprintf("Rendered resource %s does not match expected GVK", name))
}

func GetResource(resources []client.Object, name, ns, group, version, kind string) client.Object {
	for _, resource := range resources {
		gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
		if name == resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName() &&
			ns == resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace() &&
			gvk == resource.GetObjectKind().GroupVersionKind() {
			return resource
		}
	}
	return nil
}
