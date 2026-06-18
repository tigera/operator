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
	client "sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("guardian enterprise modifier", func() {

	// newObjs returns the subset of rendered guardian objects the modifier touches.
	newObjs := func() []client.Object {
		return []client.Object{
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianClusterRoleName}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}}}},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: render.GuardianServiceName, Namespace: render.GuardianNamespace},
				Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "https", Port: 443}}},
			},
			&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace},
				Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: render.GuardianContainerName}},
				}}},
			},
		}
	}

	entCtx := extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}}

	It("appends the secrets RBAC and UI settings", func() {
		out, _ := applyExtensionsWithContext(ext, render.GuardianName, entCtx, render.GuardianExtensionContext{}, newObjs(), nil)
		_, ok := extensions.FindObject[*rbacv1.Role](out, render.GuardianSecretsRole)
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*rbacv1.RoleBinding](out, render.GuardianSecretsRoleBindingName)
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*v3.UISettingsGroup](out, render.ManagerClusterSettings)
		Expect(ok).To(BeTrue())
	})

	It("adds the elasticsearch and kibana service ports", func() {
		out, _ := applyExtensionsWithContext(ext, render.GuardianName, entCtx, render.GuardianExtensionContext{}, newObjs(), nil)
		svc, _ := extensions.FindObject[*corev1.Service](out, render.GuardianServiceName)
		names := []string{}
		for _, p := range svc.Spec.Ports {
			names = append(names, p.Name)
		}
		Expect(names).To(ContainElements("https", "elasticsearch", "kibana"))
	})

	It("replaces the cluster role rules and adds impersonation", func() {
		gc := render.GuardianExtensionContext{
			Impersonation: &operatorv1.Impersonation{Users: []string{"foo"}, Groups: []string{"bar"}},
		}
		out, _ := applyExtensionsWithContext(ext, render.GuardianName, entCtx, gc, newObjs(), nil)
		role, _ := extensions.FindObject[*rbacv1.ClusterRole](out, render.GuardianClusterRoleName)

		// The single OSS placeholder rule is gone, replaced by the enterprise set.
		Expect(role.Rules).NotTo(ContainElement(rbacv1.PolicyRule{Verbs: []string{"get"}}))
		Expect(role.Rules).To(ContainElement(HaveField("ResourceNames", Equal([]string{"foo"}))))
		Expect(role.Rules).To(ContainElement(HaveField("ResourceNames", Equal([]string{"bar"}))))
	})

	It("adds the CA bundle env to the guardian container", func() {
		gc := render.GuardianExtensionContext{TrustedBundleMountPath: "/ca/bundle"}
		out, _ := applyExtensionsWithContext(ext, render.GuardianName, entCtx, gc, newObjs(), nil)
		dep, _ := extensions.FindObject[*appsv1.Deployment](out, render.GuardianDeploymentName)
		Expect(dep.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: "/ca/bundle"}))
	})

	It("does nothing for the Calico variant", func() {
		ctx := extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}}
		out, _ := applyExtensions(ext, render.GuardianName, ctx, newObjs(), nil)
		Expect(out).To(HaveLen(len(newObjs())))
		role, _ := extensions.FindObject[*rbacv1.ClusterRole](out, render.GuardianClusterRoleName)
		Expect(role.Rules).To(Equal([]rbacv1.PolicyRule{{Verbs: []string{"get"}}}))
	})
})
