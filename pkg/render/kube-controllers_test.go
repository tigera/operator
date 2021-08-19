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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/resource"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operator.InstallationSpec
	var k8sServiceEp k8sapi.ServiceEndpoint
	var esEnvs = []v1.EnvVar{
		{Name: "ELASTIC_INDEX_SUFFIX", Value: "cluster"},
		{Name: "ELASTIC_SCHEME", Value: "https"},
		{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
		{Name: "ELASTIC_PORT", Value: "9200", ValueFrom: nil},
		{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{Name: "ELASTIC_USER", Value: "",
			ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "username",
				},
			},
		},
		{Name: "ELASTIC_USERNAME", Value: "",
			ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "username",
				},
			},
		},
		{Name: "ELASTIC_PASSWORD", Value: "",
			ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "password",
				},
			},
		},
		{Name: "ELASTIC_CA", Value: "/etc/ssl/elastic/ca.pem"},
		{Name: "ES_CA_CERT", Value: "/etc/ssl/elastic/ca.pem"},
		{Name: "ES_CURATOR_BACKEND_CERT", Value: "/etc/ssl/elastic/ca.pem"},
	}

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
			{name: render.ElasticsearchKubeControllersUserSecret, ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-kube-controllers", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		component := render.KubeControllers(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, nil,
			false, dns.DefaultClusterDomain, &kubeControllersUserSecret, 0)
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
			{name: render.TigeraElasticsearchCertSecret, ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: render.ElasticsearchKubeControllersUserSecret, ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-kube-controllers", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-kube-controllers-metrics", ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(k8sServiceEp, instance, true, nil, nil, &internalManagerTLSSecret, &elasticsearchSecret, &kibanaSecret, nil,
			true, dns.DefaultClusterDomain, &kubeControllersUserSecret, 9094)
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
			Name: "ENABLED_CONTROLLERS", Value: "node,service,federatedservices,authorization,elasticsearchconfiguration",
		}))
		Expect(envs).To(ContainElements(esEnvs))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/etc/ssl/elastic/"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[1].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(dp.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(relasticsearch.PublicCertSecret))

		clusterRole := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(18))
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
			{name: render.TigeraElasticsearchCertSecret, ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: render.ElasticsearchKubeControllersUserSecret, ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-kube-controllers", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-kube-controllers-metrics", ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(k8sServiceEp, instance, true, &operator.ManagementCluster{}, nil,
			&internalManagerTLSSecret, &elasticsearchSecret, &kibanaSecret, nil, true,
			dns.DefaultClusterDomain, &kubeControllersUserSecret, 9094)
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
			Value: "node,service,federatedservices,authorization,elasticsearchconfiguration,managedcluster",
		}))
		Expect(envs).To(ContainElements(esEnvs))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/etc/ssl/elastic/"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[1].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(dp.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(relasticsearch.PublicCertSecret))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))

		// Management clusters also have a role for authenticationreviews.
		clusterRole := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(19))
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
		component := render.KubeControllers(k8sServiceEp, instance, true, nil, nil, nil, nil, nil, nil, true, dns.DefaultClusterDomain, nil, 0)
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
		component := render.KubeControllers(k8sServiceEp, instance, true, nil, nil, nil, nil, nil, nil, false, dns.DefaultClusterDomain, nil, 0)
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

		component := render.KubeControllers(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, nil, false, dns.DefaultClusterDomain, nil, 0)
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

	It("should add the OIDC prefix env variables", func() {
		instance.Variant = operator.TigeraSecureEnterprise

		authentication := &operator.Authentication{Spec: operator.AuthenticationSpec{
			UsernamePrefix: "uOIDC:",
			GroupsPrefix:   "gOIDC:",
			Openshift:      &operator.AuthenticationOpenshift{IssuerURL: "https://api.example.com"},
		}}

		component := render.KubeControllers(k8sServiceEp, instance, true, nil, nil, nil, &elasticsearchSecret, nil, authentication,
			false, dns.DefaultClusterDomain, &kubeControllersUserSecret, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
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

	When("enableESOIDCWorkaround is true", func() {
		It("should set the ENABLE_ELASTICSEARCH_OIDC_WORKAROUND env variable to true", func() {
			instance.Variant = operator.TigeraSecureEnterprise
			component := render.KubeControllers(k8sServiceEp, instance, true, nil, nil, nil, &elasticsearchSecret, nil,
				nil, true, dns.DefaultClusterDomain, &kubeControllersUserSecret, 0)
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			deployment := depResource.(*apps.Deployment)

			var esLicenseType string
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == "calico-kube-controllers" {
					for _, env := range container.Env {
						if env.Name == "ENABLE_ELASTICSEARCH_OIDC_WORKAROUND" {
							esLicenseType = env.Value
						}
					}
				}
			}

			Expect(esLicenseType).To(Equal("true"))
		})
	})

	It("should add the KUBERNETES_SERVICE_... variables", func() {
		k8sServiceEp.Host = "k8shost"
		k8sServiceEp.Port = "1234"

		component := render.KubeControllers(k8sServiceEp, instance, true, nil, nil, nil, nil, nil, nil, false, dns.DefaultClusterDomain, nil, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*apps.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not add the KUBERNETES_SERVICE_... variables on docker EE using proxy.local", func() {
		k8sServiceEp.Host = "proxy.local"
		k8sServiceEp.Port = "1234"
		instance.KubernetesProvider = operator.ProviderDockerEE

		component := render.KubeControllers(k8sServiceEp, instance, true, nil, nil, nil, nil, nil, nil, false, dns.DefaultClusterDomain, nil, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*apps.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})
})
