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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/elasticsearch"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Tigera Secure Manager rendering tests", func() {
	var instance *operator.Manager
	oidcEnvVar := corev1.EnvVar{
		Name:      "CNX_WEB_OIDC_AUTHORITY",
		Value:     "",
		ValueFrom: nil,
	}
	esusers.AddUser(elasticsearch.User{Username: render.ElasticsearchUserManager})
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Manager{
			Spec: operator.ManagerSpec{
				Auth: &operator.Auth{
					Type: operator.AuthTypeBasic,
				},
			},
		}
	})

	It("should render all resources for a default configuration", func() {
		component, err := render.Manager(instance, nil, nil, "clusterTestName", nil, nil, notOpenshift,
			&operator.Installation{Spec: operator.InstallationSpec{}}, nil,
		)
		Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(12))

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-manager", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-manager-role", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-manager-binding", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-manager-pip", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-manager-pip", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "manager-tls", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "manager-tls", ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "Deployment"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "Service"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})

	It("should handle tech preview annotation and render manager", func() {
		testCaseValues := []struct {
			annotationValue   string
			envValue          string
			includeAnnotation bool
		}{
			{annotationValue: "Enabled", envValue: "true", includeAnnotation: true},
			{annotationValue: "enabled", envValue: "true", includeAnnotation: true},
			{annotationValue: "somethingelse", envValue: "false", includeAnnotation: true},
			{annotationValue: "", envValue: "false", includeAnnotation: false},
		}
		i := 0
		for _, tcValues := range testCaseValues {
			if tcValues.includeAnnotation {
				instance.ObjectMeta.Annotations = map[string]string{
					"tech-preview.operator.tigera.io/policy-recommendation": tcValues.annotationValue,
				}
			}
			component, err := render.Manager(instance, nil, nil, "clusterTestName", nil, nil, notOpenshift,
				&operator.Installation{Spec: operator.InstallationSpec{}}, nil,
			)
			Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
			resources := component.Objects()

			// Should render the correct resource based on test case.
			Expect(len(resources)).To(Equal(12))
			Expect(GetResource(resources, "tigera-manager", "tigera-manager", "", "v1", "Deployment")).ToNot(BeNil())

			d := resources[8].(*v1.Deployment)

			Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(3))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("tigera-manager"))
			Expect(d.Spec.Template.Spec.Containers[0].Env[8].Name).To(Equal("CNX_POLICY_RECOMMENDATION_SUPPORT"))
			Expect(d.Spec.Template.Spec.Containers[0].Env[8].Value).To(Equal(tcValues.envValue))
			i++
		}
	})

	It("should render OIDC configmaps given OIDC configuration", func() {
		instance.Spec.Auth.Type = operator.AuthTypeOIDC
		oidcConfig := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ManagerOIDCConfig,
				Namespace: render.OperatorNamespace(),
			},
		}
		component, err := render.Manager(instance, nil, nil, "clusterTestName", nil, nil, notOpenshift,
			&operator.Installation{Spec: operator.InstallationSpec{}}, oidcConfig,
		)
		Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)

		// Should render the correct resource based on test case.
		resources := component.Objects()
		Expect(len(resources)).To(Equal(13))
		Expect(GetResource(resources, render.ManagerOIDCConfig, "tigera-manager", "", "v1", "ConfigMap")).ToNot(BeNil())
		d := resources[8].(*v1.Deployment)

		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(oidcEnvVar))

		// Make sure well-known and JWKS are accessible from manager.
		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerOIDCConfig))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal(render.ManagerOIDCWellknownURI))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal(render.ManagerOIDCConfig))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal(render.ManagerOIDCJwksURI))

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(4))
		Expect(d.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerOIDCConfig))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Name).To(Equal(render.ManagerOIDCConfig))
	})

	It("should set OIDC Authority environment when auth-type is OIDC", func() {
		instance.Spec.Auth.Type = operator.AuthTypeOIDC

		const authority = "https://foo.bar"
		instance.Spec.Auth.Authority = authority
		oidcEnvVar.Value = authority

		component, err := render.Manager(instance, nil, nil, "clusterTestName", nil, nil, notOpenshift,
			&operator.Installation{Spec: operator.InstallationSpec{}}, nil,
		)
		Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)

		// Should render the correct resource based on test case.
		resources := component.Objects()
		d := resources[8].(*v1.Deployment)
		// tigera-manager volumes/volumeMounts checks.
		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(oidcEnvVar))
		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
	})
})
