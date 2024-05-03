// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var (
		instance     *operatorv1.InstallationSpec
		k8sServiceEp k8sapi.ServiceEndpoint
		cfg          kubecontrollers.KubeControllersConfiguration
		cli          client.Client
	)

	esEnvs := []corev1.EnvVar{
		{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
		{Name: "ELASTIC_PORT", Value: "9200", ValueFrom: nil},
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

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		cfg = kubecontrollers.KubeControllersConfiguration{
			K8sServiceEp:      k8sServiceEp,
			Installation:      instance,
			ClusterDomain:     dns.DefaultClusterDomain,
			MetricsPort:       9094,
			TrustedBundle:     certificateManager.CreateTrustedBundle(),
			UsePSP:            true,
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}
	})

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
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
			K8sServiceEp:      k8sServiceEp,
			Installation:      instance,
			ClusterDomain:     dns.DefaultClusterDomain,
			UsePSP:            true,
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		ds := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

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
			{Name: "DISABLE_KUBE_CONTROLLERS_CONFIG_API", Value: "false"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// SecurityContext
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(999))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

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
		cfg.MetricsPort = 9094

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,service,federatedservices,usage",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))

		clusterRole := rtest.GetResource(resources, kubecontrollers.KubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(21))

		ms := rtest.GetResource(resources, kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless")
	})

	It("should render all calico kube-controllers resources using TigeraSecureEnterprise on Openshift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// We expect an extra cluster role binding.
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: "calico-kube-controllers-endpoint-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}
		instance.Variant = operatorv1.TigeraSecureEnterprise
		instance.KubernetesProvider = operatorv1.ProviderOpenShift
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))
		// Should render the correct resources.
		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
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
			{name: "calico-kube-controllers", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
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
		cfg.MetricsPort = 9094

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
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

		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))

		Expect(dp.Spec.Template.Spec.Volumes).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))

		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(19))
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "secrets"},
				Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
			}))
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
		cfg.MetricsPort = 9094

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "node,service,federatedservices,usage",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
	})
	It("should render all calico-kube-controllers resources for a default configuration using TigeraSecureEnterprise", func() {
		var defaultMode int32 = 420
		var kubeControllerTLS certificatemanagement.KeyPairInterface
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

		expectedEnv := []corev1.EnvVar{
			{Name: "TLS_KEY_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.key"},
			{Name: "TLS_CRT_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.crt"},
			{Name: "CLIENT_COMMON_NAME", Value: "calico-node-prometheus-client-tls"},
			{Name: "CA_CRT_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		}
		expectedVolumeMounts := []corev1.VolumeMount{
			{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/certs", ReadOnly: true},
			{Name: "calico-kube-controllers-metrics-tls", MountPath: "/calico-kube-controllers-metrics-tls", ReadOnly: true},
		}
		expectedVolume := []corev1.Volume{
			{
				Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-ca-bundle"},
					},
				},
			},
			{
				Name: "calico-kube-controllers-metrics-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  "calico-kube-controllers-metrics-tls",
						DefaultMode: &defaultMode,
					},
				},
			},
		}

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		kubeControllerTLS, err = certificateManager.GetOrCreateKeyPair(cli,
			kubecontrollers.KubeControllerPrometheusTLSSecret,
			common.OperatorNamespace(),
			dns.GetServiceDNSNames(kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, dns.DefaultClusterDomain))
		Expect(err).NotTo(HaveOccurred())

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.MetricsPort = 9094
		cfg.MetricsServerTLS = kubeControllerTLS

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElements(expectedEnv))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElements(expectedVolumeMounts))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes).To(ContainElements(expectedVolume))

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
			{name: "calico-kube-controllers", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
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
		cfg.MetricsPort = 9094

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "authorization,elasticsearchconfiguration,managedcluster",
		}))

		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))

		Expect(dp.Spec.Template.Spec.Volumes).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))

		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(clusterRole.Rules)).To(Equal(19))
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "secrets"},
				Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
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
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
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

	It("should render the correct env and/or images when FIPS mode is enabled (OSS)", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		cfg.Installation.FIPSMode = &fipsEnabled
		cfg.Installation.Variant = operatorv1.Calico
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == kubecontrollers.KubeController {
				Expect(container.Image).To(ContainSubstring("-fips"))
				break
			}
		}
	})

	It("should add the OIDC prefix env variables", func() {
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.LogStorageExists = true
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.MetricsPort = 9094
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
		rr1 := corev1.ResourceRequirements{
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
		rr2 := corev1.ResourceRequirements{
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
			Expect(d.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
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
			cfg.MetricsPort = 9094
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

	It("should add prometheus annotations to metrics service", func() {
		for _, variant := range []operatorv1.ProductVariant{operatorv1.Calico, operatorv1.TigeraSecureEnterprise} {
			cfg.Installation.Variant = variant
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			obj := rtest.GetResource(resources, kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, "", "v1", "Service")
			Expect(obj).ToNot(BeNil())
			svc := obj.(*corev1.Service)
			Expect(svc.Annotations["prometheus.io/scrape"]).To(Equal("true"))
			Expect(svc.Annotations["prometheus.io/port"]).To(Equal(fmt.Sprintf("%d", cfg.MetricsPort)))
		}
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

		It("policy should omit prometheus ingress rule when metrics port is 0", func() {
			// Baseline
			cfg.MetricsPort = 9094
			component := kubecontrollers.NewCalicoKubeControllersPolicy(&cfg)
			resources, _ := component.Objects()
			baselinePolicy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)

			// Zeroed policy
			cfg.MetricsPort = 0
			component = kubecontrollers.NewCalicoKubeControllersPolicy(&cfg)
			resources, _ = component.Objects()
			zeroedPolicy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)

			Expect(len(zeroedPolicy.Spec.Ingress)).To(Equal(len(baselinePolicy.Spec.Ingress) - 1))
		})

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

	It("should render init containers when certificate management is enabled", func() {
		instance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.MetricsPort = 9094
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		tls, err := certificateManager.GetOrCreateKeyPair(cli, kubecontrollers.KubeControllerPrometheusTLSSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg.MetricsServerTLS = tls

		resources, _ := kubecontrollers.NewCalicoKubeControllers(&cfg).Objects()

		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dp.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := dp.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", kubecontrollers.KubeControllerPrometheusTLSSecret)))
	})

	Context("multi-tenant rendering", func() {
		//var installation *operatorv1.InstallationSpec
		var tenant *operatorv1.Tenant
		var tenantCfg kubecontrollers.KubeControllersConfiguration
		var instance *operatorv1.InstallationSpec

		BeforeEach(func() {
			tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-tenant",
					Namespace: "test-tenant-ns",
				},
				Spec: operatorv1.TenantSpec{
					ID:      "test-tenant",
					Indices: []operatorv1.Index{},
				},
			}

			miMode := operatorv1.MultiInterfaceModeNone
			instance = &operatorv1.InstallationSpec{
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					IPPools:            []operatorv1.IPPool{{CIDR: "192.168.1.0/16"}},
					MultiInterfaceMode: &miMode,
				},
				Variant:  operatorv1.TigeraSecureEnterprise,
				Registry: "test-reg/",
			}

			certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			tenantCfg = kubecontrollers.KubeControllersConfiguration{
				K8sServiceEp:                 k8sServiceEp,
				Installation:                 instance,
				ClusterDomain:                dns.DefaultClusterDomain,
				MetricsPort:                  9094,
				TrustedBundle:                certificateManager.CreateTrustedBundle(),
				UsePSP:                       true,
				Namespace:                    tenant.Namespace,
				BindingNamespaces:            []string{tenant.Namespace},
				LogStorageExists:             true,
				ManagementCluster:            &operatorv1.ManagementCluster{},
				KubeControllersGatewaySecret: nil,
				Tenant:                       tenant,
			}
		})

		It("should render all resources", func() {
			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{name: kubecontrollers.EsKubeControllerNetworkPolicyName, ns: tenant.Namespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
				{name: kubecontrollers.MultiTenantManagedClustersAccessName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
				{name: kubecontrollers.MultiTenantManagedClustersAccessName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
				{name: kubecontrollers.KubeControllerServiceAccount, ns: tenant.Namespace, group: "", version: "v1", kind: "ServiceAccount"},
				{name: kubecontrollers.EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
				{name: kubecontrollers.EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
				{name: kubecontrollers.EsKubeController, ns: tenant.Namespace, group: "apps", version: "v1", kind: "Deployment"},
				{name: kubecontrollers.EsKubeControllerPodSecurityPolicy, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
				{name: kubecontrollers.EsKubeControllerMetrics, ns: tenant.Namespace, group: "", version: "v1", kind: "Service"},
			}

			component := kubecontrollers.NewElasticsearchKubeControllers(&tenantCfg)
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(len(expectedResources)))

			// Should render the correct resources.
			i := 0
			for _, expectedRes := range expectedResources {
				rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
				i++
			}
		})

		It("should render all multi-tenant environment variables", func() {
			component := kubecontrollers.NewElasticsearchKubeControllers(&tenantCfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// The Deployment should have the correct configuration.
			dp := rtest.GetResource(resources, kubecontrollers.EsKubeController, tenant.Namespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

			envs := dp.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElements(
				corev1.EnvVar{
					Name:  "ENABLED_CONTROLLERS",
					Value: "managedclusterlicensing",
				},
				corev1.EnvVar{
					Name:  "TENANT_NAMESPACE",
					Value: tenant.Namespace,
				},
				corev1.EnvVar{
					Name:  "TENANT_ID",
					Value: tenant.Spec.ID,
				},
				corev1.EnvVar{
					Name:  "MULTI_CLUSTER_FORWARDING_ENDPOINT",
					Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", tenant.Namespace),
				},
				corev1.EnvVar{
					Name:  "KUBE_CONTROLLERS_CONFIG_NAME",
					Value: "elasticsearch",
				},
				corev1.EnvVar{
					Name:  "DISABLE_KUBE_CONTROLLERS_CONFIG_API",
					Value: "true",
				},
			),
			)
		})

		It("should enable multi-tenant RBAC", func() {
			component := kubecontrollers.NewElasticsearchKubeControllers(&tenantCfg)
			resources, _ := component.Objects()

			cr := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts"},
					Verbs:         []string{"impersonate"},
					ResourceNames: []string{kubecontrollers.KubeControllerServiceAccount},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"groups"},
					Verbs:     []string{"impersonate"},
					ResourceNames: []string{
						serviceaccount.AllServiceAccountsGroup,
						"system:authenticated",
						fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, common.CalicoNamespace),
					},
				},
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs:     []string{"watch", "list", "get"},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))

			clusterRoleBinding := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole,
				"", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(clusterRoleBinding.RoleRef.Name).To(Equal(kubecontrollers.EsKubeControllerRole))
			Expect(clusterRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      kubecontrollers.KubeControllerServiceAccount,
					Namespace: tenant.Namespace,
				},
			}))

			managedClusterAccessClusterRole := rtest.GetResource(resources,
				kubecontrollers.MultiTenantManagedClustersAccessName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedManagedClusterAccessRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs:     []string{"get"},
				},
			}
			Expect(managedClusterAccessClusterRole.Rules).To(ContainElements(expectedManagedClusterAccessRules))

			managedClusterAccessClusterRoleBinding := rtest.GetResource(resources,
				kubecontrollers.MultiTenantManagedClustersAccessName,
				"", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(managedClusterAccessClusterRoleBinding.RoleRef.Name).To(Equal(kubecontrollers.MultiTenantManagedClustersAccessName))
			Expect(managedClusterAccessClusterRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      kubecontrollers.KubeControllerServiceAccount,
					Namespace: common.CalicoNamespace,
				},
			}))
		})
	})
})
