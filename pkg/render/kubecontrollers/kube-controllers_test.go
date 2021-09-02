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

package kubecontrollers_test

import (
	"fmt"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/testutils"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/resource"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operatorv1.InstallationSpec
	var k8sServiceEp k8sapi.ServiceEndpoint
	var cfg kubecontrollers.KubeControllersConfiguration
	var esEnvs = []corev1.EnvVar{
		{Name: "ELASTIC_INDEX_SUFFIX", Value: "cluster"},
		{Name: "ELASTIC_SCHEME", Value: "https"},
		{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
		{Name: "ELASTIC_PORT", Value: "9200", ValueFrom: nil},
		{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{Name: "ELASTIC_USER", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "username",
				},
			},
		},
		{Name: "ELASTIC_USERNAME", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "username",
				},
			},
		},
		{Name: "ELASTIC_PASSWORD", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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

		miMode := operatorv1.MultiInterfaceModeNone
		instance = &operatorv1.InstallationSpec{
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{
				IPPools:            []operatorv1.IPPool{{CIDR: "192.168.1.0/16"}},
				MultiInterfaceMode: &miMode,
			},
			Registry: "test-reg/",
		}
		k8sServiceEp = k8sapi.ServiceEndpoint{}

		// Set up a default config to pass to render.
		cfg = kubecontrollers.KubeControllersConfiguration{
			K8sServiceEp:  k8sServiceEp,
			Installation:  instance,
			ClusterDomain: dns.DefaultClusterDomain,
			MetricsPort:   9094,
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
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.KubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		cfg = kubecontrollers.KubeControllersConfiguration{
			K8sServiceEp:  k8sServiceEp,
			Installation:  instance,
			ClusterDomain: dns.DefaultClusterDomain,
		}
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
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
		ds := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		// Image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-reg/%s:%s", components.ComponentCalicoKubeControllers.Image, components.ComponentCalicoKubeControllers.Version),
		))

		// Verify env
		expectedEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "ENABLED_CONTROLLERS", Value: "node"},
			{Name: "KUBE_CONTROLLERS_CONFIG_NAME", Value: "default"},
		}
		expectedEnv = append(expectedEnv)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateCriticalAddonsOnly, rmeta.TolerateMaster))
	})

	It("should render all calico kube-controllers resources for a default configuration (standalone) using TigeraSecureEnterprise", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.ManagerInternalTLSSecretName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.KubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.ManagerInternalSecret = &testutils.InternalManagerTLSSecret
		cfg.MetricsPort = 9094

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,service,federatedservices",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		clusterRole := rtest.GetResource(resources, kubecontrollers.KubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(15))
	})

	It("should render all es-calico-kube-controllers resources for a default configuration (standalone) using TigeraSecureEnterprise when logstorage and secrets exist", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.EsKubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.TigeraElasticsearchCertSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.EsKubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.LogStorageExists = true
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.ElasticsearchSecret = &testutils.ElasticsearchSecret
		cfg.ManagerInternalSecret = &testutils.InternalManagerTLSSecret
		cfg.MetricsPort = 9094
		cfg.EnabledESOIDCWorkaround = true

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "authorization,elasticsearchconfiguration",
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

		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(16))
	})

	It("should render all calico-kube-controllers resources for a default configuration using TigeraSecureEnterprise and ClusterType is Management", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.ManagerInternalTLSSecretName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.KubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.ManagerInternalSecret = &testutils.InternalManagerTLSSecret
		cfg.MetricsPort = 9094

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "node,service,federatedservices",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))

		// Management clusters also have a role for authenticationreviews.
		clusterRole := rtest.GetResource(resources, kubecontrollers.KubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(16))
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"authenticationreviews"},
				Verbs:     []string{"create"},
			}))
	})

	It("should render all es-calico-kube-controllers resources for a default configuration using TigeraSecureEnterprise and ClusterType is Management", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.EsKubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.TigeraElasticsearchCertSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.EsKubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.LogStorageExists = true
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.ElasticsearchSecret = &testutils.ElasticsearchSecret
		cfg.ManagerInternalSecret = &testutils.InternalManagerTLSSecret
		cfg.MetricsPort = 9094
		cfg.EnabledESOIDCWorkaround = true

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "authorization,elasticsearchconfiguration,managedcluster",
		}))

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
		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
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
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.KubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		// Set node selector.
		instance.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

		// Simulate enterprise config.
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.MetricsPort = 0

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		d := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		instance.ControlPlaneTolerations = []corev1.Toleration{t}
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster))
	})

	It("should render resourcerequirements", func() {
		rr := &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		instance.ComponentResources = []operatorv1.ComponentResource{
			{
				ComponentName:        operatorv1.ComponentNameKubeControllers,
				ResourceRequirements: rr,
			},
		}

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		passed := false
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == kubecontrollers.KubeController {
				Expect(container.Resources).To(Equal(*rr))
				passed = true
			}
		}
		Expect(passed).To(Equal(true))
	})

	It("should add the OIDC prefix env variables", func() {
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.LogStorageExists = true
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.ElasticsearchSecret = &testutils.ElasticsearchSecret
		cfg.ManagerInternalSecret = &testutils.InternalManagerTLSSecret
		cfg.MetricsPort = 9094
		cfg.EnabledESOIDCWorkaround = true
		cfg.Authentication = &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{
			UsernamePrefix: "uOIDC:",
			GroupsPrefix:   "gOIDC:",
			Openshift:      &operatorv1.AuthenticationOpenshift{IssuerURL: "https://api.example.com"},
		}}

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		var usernamePrefix, groupPrefix string
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == kubecontrollers.EsKubeController {
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
			instance.Variant = operatorv1.TigeraSecureEnterprise
			cfg.LogStorageExists = true
			cfg.ManagementCluster = &operatorv1.ManagementCluster{}
			cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
			cfg.ElasticsearchSecret = &testutils.ElasticsearchSecret
			cfg.ManagerInternalSecret = &testutils.InternalManagerTLSSecret
			cfg.MetricsPort = 9094
			cfg.EnabledESOIDCWorkaround = true
			component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			deployment := depResource.(*appsv1.Deployment)

			var esLicenseType string
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == kubecontrollers.EsKubeController {
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
		cfg.K8sServiceEp = k8sServiceEp

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not add the KUBERNETES_SERVICE_... variables on docker EE using proxy.local", func() {
		k8sServiceEp.Host = "proxy.local"
		k8sServiceEp.Port = "1234"
		instance.KubernetesProvider = operatorv1.ProviderDockerEE

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})
})
