// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package extensions_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions"
)

var _ = Describe("extension registry", func() {
	AfterEach(func() {
		extensions.ResetForTest()
	})

	entCtx := extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}}

	It("applies a registered modifier to the matching component and variant", func() {
		extensions.Register(operatorv1.CalicoEnterprise, "test", extensions.Extension{
			Modify: func(ctx extensions.RenderContext, objs []client.Object) []client.Object {
				cm, ok := extensions.FindObject[*corev1.ConfigMap](objs, "cm")
				Expect(ok).To(BeTrue())
				cm.Data = map[string]string{"k": "v"}
				return append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "extra"}})
			},
		})

		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		out := extensions.ApplyModifiers("test", entCtx, in)

		Expect(out).To(HaveLen(2))
		cm := out[0].(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKeyWithValue("k", "v"))
		Expect(out[1].GetName()).To(Equal("extra"))
	})

	It("returns objects unchanged when no modifier is registered", func() {
		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		out := extensions.ApplyModifiers("unregistered", entCtx, in)
		Expect(out).To(Equal(in))
	})

	It("does not apply a modifier registered for a different variant", func() {
		extensions.Register(operatorv1.CalicoEnterprise, "test", extensions.Extension{
			Modify: func(_ extensions.RenderContext, objs []client.Object) []client.Object {
				return append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "extra"}})
			},
		})

		calicoCtx := extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}}
		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		Expect(extensions.ApplyModifiers("test", calicoCtx, in)).To(Equal(in))
	})

	It("returns objects unchanged when no installation is set", func() {
		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		Expect(extensions.ApplyModifiers("test", extensions.RenderContext{}, in)).To(Equal(in))
	})

	It("replaces rather than stacks when a (variant, component) is registered twice", func() {
		add := func(name string) extensions.Extension {
			return extensions.Extension{
				Modify: func(_ extensions.RenderContext, objs []client.Object) []client.Object {
					return append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}})
				},
			}
		}
		extensions.Register(operatorv1.CalicoEnterprise, "test", add("first"))
		extensions.Register(operatorv1.CalicoEnterprise, "test", add("second"))

		out := extensions.ApplyModifiers("test", entCtx, nil)
		Expect(out).To(HaveLen(1))
		Expect(out[0].GetName()).To(Equal("second"))
	})
})
