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
	"fmt"

	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func ExpectResource(resource runtime.Object, name, ns, group, version, kind string) {
	gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
	actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()
	Expect(actualName).To(Equal(name), fmt.Sprintf("Rendered %s resource in namespace %s has wrong name", kind, ns))
	Expect(actualNS).To(Equal(ns), fmt.Sprintf("Rendered resource %s/%s has wrong namespace", kind, name))
	Expect(resource.GetObjectKind().GroupVersionKind()).To(Equal(gvk), "Rendered resource does not match expected GVK")
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
