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

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"

	rtest "github.com/tigera/operator/pkg/render/common/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/resource"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operator.InstallationSpec
	var k8sServiceEp k8sapi.ServiceEndpoint

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
		k8sServiceEp = k8sapi.ServiceEndpoint{}
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

		component := render.KubeControllers(k8sServiceEp, instance, nil, nil,
			nil, dns.DefaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		ds := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)

		// Image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-reg/%s:%s", components.ComponentCalicoKubeControllers.Image, components.ComponentCalicoKubeControllers.Version),
		))

		// Verify env
		expectedEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "ENABLED_CONTROLLERS", Value: "node"},
		}
		expectedEnv = append(expectedEnv)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateCriticalAddonsOnly, rmeta.TolerateMaster))
	})

	It("should render all resources for a default configuration (standalone) using TigeraSecureEnterprise", func() {
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
			{name: "calico-kube-controllers-metrics", ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(k8sServiceEp, instance, nil, nil,
			&internalManagerTLSSecret, dns.DefaultClusterDomain, 9094)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(v1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,service,federatedservices",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		clusterRole := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(15))
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
			{name: "calico-kube-controllers-metrics", ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(k8sServiceEp, instance, &operator.ManagementCluster{}, nil,
			&internalManagerTLSSecret, dns.DefaultClusterDomain, 9094)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(v1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "node,service,federatedservices,managedcluster",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))

		// Management clusters also have a role for authenticationreviews.
		clusterRole := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(16))
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
		component := render.KubeControllers(k8sServiceEp, instance, nil, nil,
			nil, dns.DefaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		d := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		t := v1.Toleration{
			Key:      "foo",
			Operator: v1.TolerationOpEqual,
			Value:    "bar",
		}
		instance.ControlPlaneTolerations = []v1.Toleration{t}
		component := render.KubeControllers(k8sServiceEp, instance, nil, nil,
			nil, dns.DefaultClusterDomain, 0)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment").(*apps.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster))
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

		component := render.KubeControllers(k8sServiceEp, instance, nil, nil,
			nil, dns.DefaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
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

	It("should add the KUBERNETES_SERVICE_... variables", func() {
		k8sServiceEp.Host = "k8shost"
		k8sServiceEp.Port = "1234"

		component := render.KubeControllers(k8sServiceEp, instance, nil, nil,
			nil, dns.DefaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*apps.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})
})
