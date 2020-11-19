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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/apimachinery/pkg/api/resource"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operator.InstallationSpec

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.

		miMode := operator.MultiInterfaceModeNone
		instance = &operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools:            []operator.IPPool{{CIDR: "192.168.1.0/16"}},
				MultiInterfaceMode: &miMode,
			},
			Registry: "test-reg/",
		}

	})

	It("should render all resources for a custom configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-kube-controllers", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-kube-controllers", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "calico-kube-controllers", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		component := render.KubeControllers(instance, false, nil, nil, nil, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		ds := GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)

		// Image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-reg/%s:%s", components.ComponentCalicoKubeControllers.Image, components.ComponentCalicoKubeControllers.Version),
		))

		// Verify env
		expectedEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "ENABLED_CONTROLLERS", Value: "node"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// Verify tolerations.
		expectedTolerations := []v1.Toleration{
			{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
			{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectNoSchedule},
		}
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-kube-controllers", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-kube-controllers", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "calico-kube-controllers", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		instance.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(instance, true, nil, nil, nil, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		ds := GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)

		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
		envs := ds.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(v1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,service,federatedservices,authorization,elasticsearchconfiguration",
		}))

		clusterRole := GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(16))
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise and ClusterType is Management", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-kube-controllers", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-kube-controllers", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: render.ManagerInternalTLSSecretName, ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-kube-controllers", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		instance.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(instance, true, &operator.ManagementCluster{}, nil, &internalManagerTLSSecret, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(v1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "node,service,federatedservices,authorization,elasticsearchconfiguration,managedcluster",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))

		// Management clusters also have a role for authenticationreviews.
		clusterRole := GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(17))
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"authenticationreviews"},
				Verbs:     []string{"create"},
			}))

	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-kube-controllers", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-kube-controllers", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-kube-controllers", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "calico-kube-controllers", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		instance.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		instance.Variant = operator.TigeraSecureEnterprise
		component := render.KubeControllers(instance, true, nil, nil, nil, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		d := GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should render resourcerequirements", func() {
		rr := &v1.ResourceRequirements{
			Requests: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("250m"),
				v1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("500m"),
				v1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		instance.ComponentResources = []operator.ComponentResource{
			{
				ComponentName:        operator.ComponentNameKubeControllers,
				ResourceRequirements: rr,
			},
		}

		component := render.KubeControllers(instance, false, nil, nil, nil, nil)
		resources, _ := component.Objects()

		depResource := GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*apps.Deployment)

		passed := false
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == "calico-kube-controllers" {
				Expect(container.Resources).To(Equal(*rr))
				passed = true
			}
		}
		Expect(passed).To(Equal(true))
	})

	It("should add the OIDC prefix env variables", func() {
		instance.Variant = operator.TigeraSecureEnterprise

		authentication := &operator.Authentication{Spec: operator.AuthenticationSpec{
			UsernamePrefix: "uOIDC:",
			GroupsPrefix:   "gOIDC:",
			Openshift:      &operator.AuthenticationOpenshift{IssuerURL: "https://api.example.com"},
		}}

		component := render.KubeControllers(instance, true, nil, nil, nil, authentication)
		resources, _ := component.Objects()

		depResource := GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*apps.Deployment)

		var usernamePrefix, groupPrefix string
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == "calico-kube-controllers" {
				for _, env := range container.Env {
					if env.Name == "OIDC_AUTH_USERNAME_PREFIX" {
						usernamePrefix = env.Value
					} else if env.Name == "OIDC_AUTH_GROUP_PREFIX" {
						groupPrefix = env.Value
					}
				}
			}
		}

		Expect(usernamePrefix).To(Equal("uOIDC:"))
		Expect(groupPrefix).To(Equal("gOIDC:"))
	})
})
