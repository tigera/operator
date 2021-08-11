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
	"bufio"
	"bytes"
	"fmt"

	rtest "github.com/tigera/operator/pkg/render/common/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

var _ = Describe("Rendering tests", func() {
	var instance *operator.InstallationSpec
	var logBuffer bytes.Buffer
	var logWriter *bufio.Writer
	var typhaNodeTLS *render.TyphaNodeTLS
	one := intstr.FromInt(1)
	miMode := operator.MultiInterfaceModeNone
	k8sServiceEp := k8sapi.ServiceEndpoint{}

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.InstallationSpec{
			CNI: &operator.CNISpec{
				Type: operator.PluginCalico,
				IPAM: &operator.IPAMSpec{
					Type: operator.IPAMPluginCalico,
				},
			},
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools:            []operator.IPPool{{CIDR: "192.168.1.0/16"}},
				MultiInterfaceMode: &miMode,
			},
			Registry: "test-reg/",
			NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &one,
				},
			},
		}

		logWriter = bufio.NewWriter(&logBuffer)
		render.SetTestLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(logWriter)))
		typhaNodeTLS = &render.TyphaNodeTLS{}
	})
	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			logWriter.Flush()
			fmt.Printf("Logs:\n%s\n", logBuffer.String())
		}
	})

	It("should render all resources for a default configuration", func() {
		// For this scenario, we expect the basic resources
		// created by the controller without any optional ones. These include:
		// - 6 node resources (ServiceAccount, ClusterRole, Binding, ConfigMap, DaemonSet, PodSecurityPolicy)
		// - 4 secrets for Typha comms (2 in operator namespace and 2 in calico namespace)
		// - 2 ConfigMap for Typha comms (1 in operator namespace and 1 in calico namespace)
		// - 7 typha resources (Service, SA, Role, Binding, Deployment, PodDisruptionBudget, PodSecurityPolicy)
		// - 6 kube-controllers resources (ServiceAccount, ClusterRole, Binding, Deployment, PodSecurityPolicy, Service, Secret)
		// - 1 namespace
		// - 1 PriorityClass
		c, err := render.Calico(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operator.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c.Render())).To(Equal(6 + 4 + 2 + 7 + 6 + 1 + 1))
	})

	It("should render all resources when variant is Tigera Secure", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure:
		// - X Same as default config
		// - 1 Service to expose calico/node metrics.
		// - 1 ns (tigera-dex)
		var nodeMetricsPort int32 = 9081
		instance.Variant = operator.TigeraSecureEnterprise
		instance.NodeMetricsPort = &nodeMetricsPort
		c, err := render.Calico(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operator.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c.Render())).To(Equal((6 + 4 + 2 + 7 + 6 + 1 + 1) + 1 + 1))
	})

	It("should render all resources when variant is Tigera Secure and Management Cluster", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure:
		// - X Same as default config for EE
		// - pass in internalManagerTLSSecret
		var nodeMetricsPort int32 = 9081
		instance.Variant = operator.TigeraSecureEnterprise
		instance.NodeMetricsPort = &nodeMetricsPort

		internalManagerTLSSecret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: render.ManagerInternalTLSSecretName, Namespace: rmeta.OperatorNamespace(),
			},
		}
		c, err := render.Calico(k8sServiceEp, instance, &operator.ManagementCluster{}, nil, nil, typhaNodeTLS, internalManagerTLSSecret, nil, operator.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{render.PriorityClassName, "", "scheduling.k8s.io", "v1", "PriorityClass"},
			{common.CalicoNamespace, "", "", "v1", "Namespace"},
			{render.DexObjectName, "", "", "v1", "Namespace"},
			{render.TyphaCAConfigMapName, rmeta.OperatorNamespace(), "", "v1", "ConfigMap"},
			{render.TyphaCAConfigMapName, common.CalicoNamespace, "", "v1", "ConfigMap"},
			{render.TyphaTLSSecretName, rmeta.OperatorNamespace(), "", "v1", "Secret"},
			{render.NodeTLSSecretName, rmeta.OperatorNamespace(), "", "v1", "Secret"},
			{render.TyphaTLSSecretName, common.CalicoNamespace, "", "v1", "Secret"},
			{render.NodeTLSSecretName, common.CalicoNamespace, "", "v1", "Secret"},
			{render.ManagerInternalTLSSecretName, rmeta.OperatorNamespace(), "", "v1", "Secret"},
			{render.TyphaServiceAccountName, common.CalicoNamespace, "", "v1", "ServiceAccount"},
			{"calico-typha", "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{"calico-typha", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{common.TyphaDeploymentName, common.CalicoNamespace, "", "v1", "Deployment"},
			{render.TyphaServiceName, common.CalicoNamespace, "", "v1", "Service"},
			{common.TyphaDeploymentName, common.CalicoNamespace, "policy", "v1beta1", "PodDisruptionBudget"},
			{common.TyphaDeploymentName, "", "policy", "v1beta1", "PodSecurityPolicy"},
			{"calico-node", common.CalicoNamespace, "", "v1", "ServiceAccount"},
			{"calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{"calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{"calico-node-metrics", common.CalicoNamespace, "", "v1", "Service"},
			{"cni-config", common.CalicoNamespace, "", "v1", "ConfigMap"},
			{common.NodeDaemonSetName, "", "policy", "v1beta1", "PodSecurityPolicy"},
			{common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet"},
			{"calico-kube-controllers", common.CalicoNamespace, "", "v1", "ServiceAccount"},
			{"calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{"calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{"calico-kube-controllers", common.CalicoNamespace, "apps", "v1", "Deployment"},
			{render.ManagerInternalTLSSecretName, common.CalicoNamespace, "", "v1", "Secret"},
			{"calico-kube-controllers", "", "policy", "v1beta1", "PodSecurityPolicy"},
			{"calico-kube-controllers-metrics", common.CalicoNamespace, "", "v1", "Service"},
		}

		var resources []client.Object
		for _, component := range c.Render() {
			var toCreate, _ = component.Objects()
			resources = append(resources, toCreate...)
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render calico with a apparmor profile if annotation is present in installation", func() {
		apparmorProf := "foobar"
		r, err := render.Calico(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operator.ProviderNone, nil, false, apparmorProf, dns.DefaultClusterDomain, 0, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		comps := r.Render()
		var cn *appsv1.DaemonSet
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			if r != nil {
				cn = r.(*appsv1.DaemonSet)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.ObjectMeta.Annotations["container.apparmor.security.beta.kubernetes.io/calico-node"]).To(Equal(apparmorProf))
	})

	It("should handle BGP layout ConfigMap", func() {
		bgpLayout := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			Data: map[string]string{
				render.BGPLayoutConfigMapKey: "",
			},
		}
		bgpLayout.Name = "bgp-layout"
		bgpLayout.Namespace = "tigera-operator"
		r, err := render.Calico(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operator.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 0, 0, bgpLayout, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		comps := r.Render()
		var cm *corev1.ConfigMap
		var ds *appsv1.DaemonSet
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, "bgp-layout", "calico-system", "", "v1", "ConfigMap")
			if r != nil {
				cm = r.(*corev1.ConfigMap)
			}
			r = rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			if r != nil {
				ds = r.(*appsv1.DaemonSet)
			}
		}
		Expect(cm).ToNot(BeNil())
		Expect(ds).ToNot(BeNil())
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/bgp-layout"))
		Expect(ds.Spec.Template.Annotations["hash.operator.tigera.io/bgp-layout"]).NotTo(BeEmpty())
	})

	It("should handle collectProcessPath in logCollector", func() {
		testNode := func(processPath operator.CollectProcessPathOption, expectedHostPID bool) {
			var logCollector operator.LogCollector
			logCollector.Spec.CollectProcessPath = &processPath
			r, err := render.Calico(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operator.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, &logCollector)
			Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
			comps := r.Render()
			var ds *appsv1.DaemonSet
			for _, comp := range comps {
				resources, _ := comp.Objects()
				r := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				if r != nil {
					ds = r.(*appsv1.DaemonSet)
				}
			}
			checkEnvVar := func(ds *appsv1.DaemonSet) bool {
				envPresent := false
				for _, env := range ds.Spec.Template.Spec.Containers[0].Env {
					if env.Name == "FELIX_FLOWLOGSCOLLECTPROCESSPATH" {
						envPresent = true
						if env.Value == "true" {
							return true
						}
					}
				}
				return !envPresent
			}
			Expect(ds).ToNot(BeNil())
			Expect(ds.Spec.Template.Spec.HostPID).To(Equal(expectedHostPID))
			Expect(checkEnvVar(ds)).To(Equal(true))
		}
		testNode(operator.CollectProcessPathEnable, true)
		testNode(operator.CollectProcessPathDisable, false)
	})
})

func componentCount(components []render.Component) int {
	count := 0
	for _, c := range components {
		objsToCreate, _ := c.Objects()
		count += len(objsToCreate)
	}
	return count
}
