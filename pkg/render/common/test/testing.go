// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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

package test

import (
	"bytes"
	"encoding/json"
	"fmt"

	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func ExpectNoK8sServiceEpEnvVars(podSpec corev1.PodSpec) {
	for _, c := range podSpec.Containers {
		for _, ev := range c.Env {
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_HOST"))
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_PORT"))
		}
	}
	for _, c := range podSpec.InitContainers {
		for _, ev := range c.Env {
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_HOST"))
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_PORT"))
		}
	}
}

func ExpectResourceInList(objs []client.Object, name, ns, group, version, kind string) {
	type expectedResource struct {
		Name      string
		Namespace string
		GVK       schema.GroupVersionKind
	}

	o := expectedResource{
		Name:      name,
		Namespace: ns,
		GVK:       schema.GroupVersionKind{Group: group, Version: version, Kind: kind},
	}

	elems := []expectedResource{}
	for _, obj := range objs {
		elems = append(elems, expectedResource{
			Name:      obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
			Namespace: obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
			GVK:       obj.GetObjectKind().GroupVersionKind(),
		})
	}
	Expect(elems).To(ContainElement(o))
}

func ExpectResource(resource runtime.Object, name, ns, group, version, kind string) {
	gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
	actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()
	ExpectWithOffset(1, actualName).To(Equal(name), fmt.Sprintf("Rendered %s resource in namespace %s has wrong name", kind, ns))
	ExpectWithOffset(1, actualNS).To(Equal(ns), fmt.Sprintf("Rendered resource %s/%s has wrong namespace", kind, name))
	ExpectWithOffset(1, resource.GetObjectKind().GroupVersionKind()).To(Equal(gvk), fmt.Sprintf("Rendered resource %s does not match expected GVK", name))
}

func GetResource(resources []client.Object, name, ns, group, version, kind string) client.Object {
	for _, resource := range resources {
		gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
		om := resource.(metav1.ObjectMetaAccessor).GetObjectMeta()
		if name == om.GetName() &&
			ns == om.GetNamespace() &&
			gvk == resource.GetObjectKind().GroupVersionKind() {
			return resource
		}
	}
	return nil
}

func GetContainer(containers []v1.Container, name string) *v1.Container {
	for _, container := range containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func ExpectGlobalReportType(resource runtime.Object, name string) {
	actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	Expect(actualName).To(Equal(name), "Rendered resource has wrong name")
	gvk := schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "GlobalReportType"}
	Expect(resource.GetObjectKind().GroupVersionKind()).To(Equal(gvk), fmt.Sprintf("Rendered resource %s does not match expected GVK", name))
	v, ok := resource.(*v3.GlobalReportType)
	Expect(ok).To(BeTrue(), fmt.Sprintf("resource (%v) should convert to GlobalReportType", resource))
	Expect(v.Spec.UISummaryTemplate.Template).ToNot(BeEmpty())
	_, err := json.Marshal(v.Spec.UISummaryTemplate.Template)
	Expect(err).To(BeNil())
	for _, t := range v.Spec.DownloadTemplates {
		Expect(t.Template).ToNot(BeEmpty(), fmt.Sprintf("%s template should not be empty", t.Name))
		_, err = json.Marshal(t.Template)
		Expect(err).To(BeNil())
	}
}

func ExpectGlobalAlertTemplateToBePopulated(resource runtime.Object) {
	v, ok := resource.(*v3.GlobalAlertTemplate)
	Expect(ok).To(BeTrue(), fmt.Sprintf("resource (%v) should convert to GlobalAlertTemplate", resource))
	Expect(v.Spec.Description).ToNot(BeEmpty(), fmt.Sprintf("Description should not be empty for resource (%v)", resource))
	Expect(v.Spec.Severity).ToNot(BeNumerically("==", 0), fmt.Sprintf("Severity should not be empty for resource (%v)", resource))

	if v.Spec.Type != v3.GlobalAlertTypeAnomalyDetection { // ignored for  AnomalyDetection Typed
		Expect(v.Spec.DataSet).ToNot(BeEmpty(), fmt.Sprintf("DataSet should not be empty for resource (%v)", resource))
	}
}

func ExpectEnv(env []v1.EnvVar, key, value string) {
	for _, e := range env {
		if e.Name == key {
			Expect(e.Value).To(Equal(value))
			return
		}
	}
	Expect(false).To(BeTrue(), fmt.Sprintf("Missing expected environment variable %s", key))
}

func ExpectVolumeMount(vms []v1.VolumeMount, name, path string) {
	for _, vm := range vms {
		if vm.Name == name {
			Expect(vm.MountPath).To(Equal(path))
			return
		}
	}
	Expect(false).To(BeTrue(), fmt.Sprintf("Missing expected volume mount %s", name))
}

// CreateCertSecret creates a secret that is not signed by the certificate manager, making it useful for testing legacy
// operator secrets or secrets that are brought to the cluster by the customer.
func CreateCertSecret(name, namespace string, dnsNames ...string) *corev1.Secret {
	cryptoCA, _ := tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix + "@some-hash")
	cfg, _ := cryptoCA.MakeServerCertForDuration(sets.NewString(dnsNames...), rmeta.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
	keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
	_ = cfg.WriteCertConfig(crtContent, keyContent)

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyContent.Bytes(),
			corev1.TLSCertKey:       crtContent.Bytes(),
		},
	}
}
