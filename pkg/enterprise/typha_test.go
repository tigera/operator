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

package enterprise_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions/extensionstest"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("typha enterprise modifier", func() {

	multiMode := operatorv1.MultiInterfaceModeMultus

	newObjs := func() []client.Object {
		return []client.Object{
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-typha"}},
			&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-typha"},
				Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: render.TyphaContainerName}},
				}}},
			},
		}
	}

	It("adds enterprise RBAC and MULTI_INTERFACE_MODE for the enterprise variant", func() {
		ctx := render.RenderContext{Installation: &operatorv1.InstallationSpec{
			Variant:       operatorv1.CalicoEnterprise,
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{MultiInterfaceMode: &multiMode},
		}}
		out, _ := extensionstest.ApplyExtensions(ext, render.ComponentNameTypha, ctx, newObjs(), nil)

		role := out[0].(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))

		dep := out[1].(*appsv1.Deployment)
		var c *corev1.Container
		for i := range dep.Spec.Template.Spec.Containers {
			if dep.Spec.Template.Spec.Containers[i].Name == render.TyphaContainerName {
				c = &dep.Spec.Template.Spec.Containers[i]
			}
		}
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: multiMode.Value()}))
	})

	It("is a no-op for the Calico variant", func() {
		ctx := render.RenderContext{Installation: &operatorv1.InstallationSpec{
			Variant:       operatorv1.Calico,
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{MultiInterfaceMode: &multiMode},
		}}
		out, _ := extensionstest.ApplyExtensions(ext, render.ComponentNameTypha, ctx, newObjs(), nil)
		Expect(out[0].(*rbacv1.ClusterRole).Rules).To(BeEmpty())
		dep := out[1].(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers[0].Env).To(BeEmpty())
	})

	It("does not panic on a zero Context (nil Installation)", func() {
		out, _ := extensionstest.ApplyExtensions(ext, render.ComponentNameTypha, render.RenderContext{}, newObjs(), nil)
		Expect(out[0].(*rbacv1.ClusterRole).Rules).To(BeEmpty())
	})
})
