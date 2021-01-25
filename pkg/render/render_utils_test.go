// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package render_test

import (
	"encoding/json"
	"fmt"

	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

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
	Expect(v.Spec.DataSet).ToNot(BeEmpty(), fmt.Sprintf("DataSet should not be empty for resource (%v)", resource))
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

var (
	tolerateMaster = corev1.Toleration{
		Key:    "node-role.kubernetes.io/master",
		Effect: corev1.TaintEffectNoSchedule,
	}

	tolerateCriticalAddonsOnly = corev1.Toleration{
		Key:      "CriticalAddonsOnly",
		Operator: v1.TolerationOpExists,
	}

	tolerateAll = []corev1.Toleration{
		{
			Key:      "CriticalAddonsOnly",
			Operator: corev1.TolerationOpExists,
		},
		{
			Effect:   corev1.TaintEffectNoSchedule,
			Operator: corev1.TolerationOpExists,
		},
		{
			Effect:   corev1.TaintEffectNoExecute,
			Operator: corev1.TolerationOpExists,
		},
	}
)
