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
	var s *extensions.Set
	BeforeEach(func() {
		s = extensions.NewSet()
	})

	entCtx := extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}}

	It("applies a registered modifier to the matching component and variant", func() {
		s.Variant(operatorv1.CalicoEnterprise).Modify("test", func(ctx extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
			cm, ok := extensions.FindObject[*corev1.ConfigMap](objs, "cm")
			Expect(ok).To(BeTrue())
			cm.Data = map[string]string{"k": "v"}
			return append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "extra"}}), del
		})

		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		out, _ := applyExtensions(s, "test", entCtx, in, nil)

		Expect(out).To(HaveLen(2))
		cm := out[0].(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKeyWithValue("k", "v"))
		Expect(out[1].GetName()).To(Equal("extra"))
	})

	It("lets a modifier append to the delete list", func() {
		s.Variant(operatorv1.CalicoEnterprise).Modify("test", func(_ extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
			return objs, append(del, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "stale"}})
		})

		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		out, del := applyExtensions(s, "test", entCtx, in, nil)
		Expect(out).To(Equal(in))
		Expect(del).To(HaveLen(1))
		Expect(del[0].GetName()).To(Equal("stale"))
	})

	It("returns objects unchanged when no modifier is registered", func() {
		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		out, _ := applyExtensions(s, "unregistered", entCtx, in, nil)
		Expect(out).To(Equal(in))
	})

	It("does not apply a modifier registered for a different variant", func() {
		s.Variant(operatorv1.CalicoEnterprise).Modify("test", func(_ extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
			return append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "extra"}}), del
		})

		calicoCtx := extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}}
		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		out, _ := applyExtensions(s, "test", calicoCtx, in, nil)
		Expect(out).To(Equal(in))
	})

	It("returns objects unchanged when no installation is set", func() {
		in := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}}
		out, _ := applyExtensions(s, "test", extensions.RenderContext{}, in, nil)
		Expect(out).To(Equal(in))
	})

	It("replaces rather than stacks when a component modifier is registered twice", func() {
		add := func(name string) {
			s.Variant(operatorv1.CalicoEnterprise).Modify("test", func(_ extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
				return append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}}), del
			})
		}
		add("first")
		add("second")

		out, _ := applyExtensions(s, "test", entCtx, nil, nil)
		Expect(out).To(HaveLen(1))
		Expect(out[0].GetName()).To(Equal("second"))
	})
})
