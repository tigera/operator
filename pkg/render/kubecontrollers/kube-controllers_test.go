// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

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

	"k8s.io/apimachinery/pkg/types"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operatorv1.InstallationSpec
	var k8sServiceEp k8sapi.ServiceEndpoint
	var cfg kubecontrollers.KubeControllersConfiguration
	var internalManagerTLSSecret certificatemanagement.KeyPairInterface
	esEnvs := []corev1.EnvVar{
		{Name: "ELASTIC_INDEX_SUFFIX", Value: "cluster"},
		{Name: "ELASTIC_SCHEME", Value: "https"},
		{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
		{Name: "ELASTIC_PORT", Value: "9200", ValueFrom: nil},
		{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{
			Name: "ELASTIC_USER", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "username",
				},
			},
		},
		{
			Name: "ELASTIC_USERNAME", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "username",
				},
			},
		},
		{
			Name: "ELASTIC_PASSWORD", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "password",
				},
			},
		},
		{Name: "ELASTIC_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
		{Name: "ES_CA_CERT", Value: certificatemanagement.TrustedCertBundleMountPath},
		{Name: "ES_CURATOR_BACKEND_CERT", Value: certificatemanagement.TrustedCertBundleMountPath},
	}
	expectedPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers.json")
	expectedPolicyForUnmanagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_ocp.json")
	expectedPolicyForManaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_managed.json")
	expectedPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_managed_ocp.json")
	expectedESPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/es-kubecontrollers.json")
	expectedESPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/es-kubecontrollers_ocp.json")

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

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain)
		Expect(err).NotTo(HaveOccurred())
		internalManagerTLSSecret, err = certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		cfg = kubecontrollers.KubeControllersConfiguration{
			K8sServiceEp:  k8sServiceEp,
			Installation:  instance,
			ClusterDomain: dns.DefaultClusterDomain,
			MetricsPort:   9094,
			TrustedBundle: certificateManager.CreateTrustedBundle(),
			UsePSP:        true,
		}
	})

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind()).NotTo(Equal("PodSecurityPolicy"))
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
			UsePSP:        true,
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
			{Name: "FIPS_MODE_ENABLED", Value: "false"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateCriticalAddonsAndControlPlane))
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
			{name: kubecontrollers.KubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.ManagerInternalSecret = internalManagerTLSSecret
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

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/internal-manager-tls"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		clusterRole := rtest.GetResource(resources, kubecontrollers.KubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(19))
	})

	It("should render all es-calico-kube-controllers resources for a default configuration (standalone) using TigeraSecureEnterprise when logstorage and secrets exist", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.EsKubeControllerNetworkPolicyName, ns: common.CalicoNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: kubecontrollers.EsKubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.EsKubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: kubecontrollers.EsKubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.LogStorageExists = true
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.ManagerInternalSecret = internalManagerTLSSecret
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
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/internal-manager-tls"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal(certificatemanagement.TrustedCertVolumeMountPath))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[1].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(dp.Spec.Template.Spec.Volumes[1].ConfigMap.Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))

		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(20))
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
			{name: kubecontrollers.KubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.ManagerInternalSecret = internalManagerTLSSecret
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

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/internal-manager-tls"))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
	})

	It("should render all es-calico-kube-controllers resources for a default configuration using TigeraSecureEnterprise and ClusterType is Management", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.EsKubeControllerNetworkPolicyName, ns: common.CalicoNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: kubecontrollers.EsKubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.EsKubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: kubecontrollers.EsKubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.LogStorageExists = true
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.ManagerInternalSecret = internalManagerTLSSecret
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
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/internal-manager-tls"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal(certificatemanagement.TrustedCertVolumeMountPath))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dp.Spec.Template.Spec.Volumes[1].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(dp.Spec.Template.Spec.Volumes[1].ConfigMap.Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))

		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(20))
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
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
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
		cfg.ManagerInternalSecret = internalManagerTLSSecret
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

	Context("With calico-kube-controllers overrides", func() {
		var rr1 = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}
		var rr2 = corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		It("should handle calicoKubeControllersDeployment overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{
								{
									Name:      "calico-kube-controllers",
									Resources: &rr1,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}

			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			Expect(d.Labels).To(HaveLen(1))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(1))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-kube-controllers". But the calico-kube-controllers deployment object
			// produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(1))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 3 template-level annotations
			// - 1 added by the operator by default because TrustedBundle was set on kubecontrollerconfiguration.
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(2))
			Expect(d.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/tigera-ca-private"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-kube-controllers"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
		})

		It("should override ComponentResources", func() {
			instance.ComponentResources = []operatorv1.ComponentResource{
				{
					ComponentName:        operatorv1.ComponentNameKubeControllers,
					ResourceRequirements: &rr1,
				},
			}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{
								{
									Name:      "calico-kube-controllers",
									Resources: &rr2,
								},
							},
						},
					},
				},
			}

			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-kube-controllers"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr2))
		})

		It("should override ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			// nodeSelectors are merged
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
		})

		It("should override ControlPlaneTolerations when specified", func() {
			cfg.Installation.ControlPlaneTolerations = rmeta.TolerateControlPlane

			tol := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})
	})

	When("enableESOIDCWorkaround is true", func() {
		It("should set the ENABLE_ELASTICSEARCH_OIDC_WORKAROUND env variable to true", func() {
			instance.Variant = operatorv1.TigeraSecureEnterprise
			cfg.LogStorageExists = true
			cfg.ManagementCluster = &operatorv1.ManagementCluster{}
			cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
			cfg.ManagerInternalSecret = internalManagerTLSSecret
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

	Context("kube-controllers allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.kube-controller-access", Namespace: "calico-system"}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				if scenario.Openshift {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
				} else {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
				}
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
				} else {
					cfg.ManagementClusterConnection = nil
				}
				instance.Variant = operatorv1.TigeraSecureEnterprise
				cfg.ManagerInternalSecret = internalManagerTLSSecret

				component := kubecontrollers.NewCalicoKubeControllersPolicy(&cfg)
				resources, _ := component.Objects()

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := testutils.SelectPolicyByClusterTypeAndProvider(
					scenario,
					expectedPolicyForUnmanaged,
					expectedPolicyForUnmanagedOCP,
					expectedPolicyForManaged,
					expectedPolicyForManagedOCP,
				)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
		)
	})

	Context("es-kube-controllers allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.es-kube-controller-access", Namespace: "calico-system"}

		getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if scenario.ManagedCluster {
				return nil
			}

			return testutils.SelectPolicyByProvider(scenario, expectedESPolicy, expectedESPolicyForOpenshift)
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				if scenario.Openshift {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
				} else {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
				}
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
				} else {
					cfg.ManagementClusterConnection = nil
				}
				instance.Variant = operatorv1.TigeraSecureEnterprise
				cfg.LogStorageExists = true
				cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
				cfg.ManagerInternalSecret = internalManagerTLSSecret
				cfg.EnabledESOIDCWorkaround = true

				component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
				resources, _ := component.Objects()

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
		)
	})
})
