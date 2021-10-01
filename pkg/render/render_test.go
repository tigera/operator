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
	glog "log"
	"reflect"

	"github.com/tigera/operator/pkg/render/kubecontrollers"

	rtest "github.com/tigera/operator/pkg/render/common/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
)

// allCalicoComponents takes the given configuration and returns all the components
// associated with installing Calico's core, similar to how the core_controller behaves.
func allCalicoComponents(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operatorv1.InstallationSpec,
	managementCluster *operatorv1.ManagementCluster,
	managementClusterConnection *operatorv1.ManagementClusterConnection,
	pullSecrets []*corev1.Secret,
	typhaNodeTLS *render.TyphaNodeTLS,
	managerInternalTLSSecret *corev1.Secret,
	bt map[string]string,
	p operatorv1.Provider,
	aci *operatorv1.AmazonCloudIntegration,
	up bool,
	nodeAppArmorProfile string,
	clusterDomain string,
	kubeControllersMetricsPort int,
	nodeReporterMetricsPort int,
	bgpLayout *corev1.ConfigMap,
	logCollector *operatorv1.LogCollector,
) ([]render.Component, error) {

	namespaces := render.Namespaces(cr, pullSecrets)

	objs := []client.Object{}
	if typhaNodeTLS.CAConfigMap != nil {
		objs = append(objs, typhaNodeTLS.CAConfigMap)
	}
	if bgpLayout != nil {
		objs = append(objs, bgpLayout)
	}
	if typhaNodeTLS.NodeSecret != nil {
		objs = append(objs, typhaNodeTLS.NodeSecret)
	}
	if typhaNodeTLS.TyphaSecret != nil {
		objs = append(objs, typhaNodeTLS.TyphaSecret)
	}
	if managerInternalTLSSecret != nil {
		objs = append(objs, managerInternalTLSSecret)
	}
	secretsAndConfigMaps := render.NewPassthrough(objs)

	nodeCfg := &render.NodeConfiguration{
		K8sServiceEp:            k8sServiceEp,
		Installation:            cr,
		TLS:                     typhaNodeTLS,
		NodeAppArmorProfile:     nodeAppArmorProfile,
		ClusterDomain:           clusterDomain,
		AmazonCloudIntegration:  aci,
		NodeReporterMetricsPort: nodeReporterMetricsPort,
		BGPLayouts:              bgpLayout,
		LogCollector:            logCollector,
		BirdTemplates:           bt,
		MigrateNamespaces:       up,
	}
	typhaCfg := &render.TyphaConfiguration{
		K8sServiceEp:           k8sServiceEp,
		Installation:           cr,
		TLS:                    typhaNodeTLS,
		ClusterDomain:          clusterDomain,
		AmazonCloudIntegration: aci,
		MigrateNamespaces:      up,
	}
	kcCfg := &kubecontrollers.KubeControllersConfiguration{
		K8sServiceEp:                k8sServiceEp,
		Installation:                cr,
		ManagementCluster:           managementCluster,
		ManagementClusterConnection: managementClusterConnection,
		ManagerInternalSecret:       managerInternalTLSSecret,
		ClusterDomain:               clusterDomain,
		MetricsPort:                 kubeControllersMetricsPort,
	}

	return []render.Component{namespaces, secretsAndConfigMaps, render.Typha(typhaCfg), render.Node(nodeCfg), kubecontrollers.NewCalicoKubeControllers(kcCfg)}, nil
}

var _ = Describe("Rendering tests", func() {
	var instance *operatorv1.InstallationSpec
	var logBuffer bytes.Buffer
	var logWriter *bufio.Writer
	var typhaNodeTLS *render.TyphaNodeTLS
	one := intstr.FromInt(1)
	miMode := operatorv1.MultiInterfaceModeNone
	k8sServiceEp := k8sapi.ServiceEndpoint{}

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1.InstallationSpec{
			CNI: &operatorv1.CNISpec{
				Type: operatorv1.PluginCalico,
				IPAM: &operatorv1.IPAMSpec{
					Type: operatorv1.IPAMPluginCalico,
				},
			},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{
				IPPools:            []operatorv1.IPPool{{CIDR: "192.168.1.0/16"}},
				MultiInterfaceMode: &miMode,
			},
			Registry: "test-reg/",
			NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &one,
				},
			},
		}

		nodeSecret := corev1.Secret{}
		nodeSecret.Name = render.NodeTLSSecretName
		nodeSecret.Namespace = common.OperatorNamespace()
		nodeSecret.Data = map[string][]byte{"k": []byte("v")}
		nodeSecret.Kind = "Secret"
		nodeSecret.APIVersion = "v1"

		typhaSecret := corev1.Secret{}
		typhaSecret.Name = render.TyphaTLSSecretName
		typhaSecret.Namespace = common.OperatorNamespace()
		typhaSecret.Data = map[string][]byte{"k": []byte("v")}
		typhaSecret.Kind = "Secret"
		typhaSecret.APIVersion = "v1"

		logWriter = bufio.NewWriter(&logBuffer)
		render.SetTestLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(logWriter)))
		typhaNodeTLS = &render.TyphaNodeTLS{
			CAConfigMap: &corev1.ConfigMap{Data: map[string]string{}},
			TyphaSecret: &typhaSecret,
			NodeSecret:  &nodeSecret,
		}
		typhaNodeTLS.CAConfigMap.Name = render.TyphaCAConfigMapName
		typhaNodeTLS.CAConfigMap.Namespace = common.OperatorNamespace()
		typhaNodeTLS.CAConfigMap.Kind = "ConfigMap"
		typhaNodeTLS.CAConfigMap.APIVersion = "v1"
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
		c, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c)).To(Equal(6 + 4 + 2 + 7 + 6 + 1))
	})

	It("should render all resources when variant is Tigera Secure", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure:
		// - X Same as default config
		// - 1 Service to expose calico/node metrics.
		// - 1 ns (tigera-dex)
		var nodeMetricsPort int32 = 9081
		instance.Variant = operatorv1.TigeraSecureEnterprise
		instance.NodeMetricsPort = &nodeMetricsPort
		c, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c)).To(Equal((6 + 4 + 2 + 7 + 6 + 1) + 1 + 1))
	})

	It("should render all resources when variant is Tigera Secure and Management Cluster", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure:
		// - X Same as default config for EE
		// - pass in InternalManagerTLSSecret
		var nodeMetricsPort int32 = 9081
		instance.Variant = operatorv1.TigeraSecureEnterprise
		instance.NodeMetricsPort = &nodeMetricsPort

		internalManagerTLSSecret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: render.ManagerInternalTLSSecretName, Namespace: common.OperatorNamespace(),
			},
		}
		c, err := allCalicoComponents(k8sServiceEp, instance, &operatorv1.ManagementCluster{}, nil, nil, typhaNodeTLS, internalManagerTLSSecret, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// Namespaces first.
			{common.CalicoNamespace, "", "", "v1", "Namespace"},
			{render.DexObjectName, "", "", "v1", "Namespace"},

			// Secrets and configmaps from tigera-operator namespace.
			{render.TyphaCAConfigMapName, common.OperatorNamespace(), "", "v1", "ConfigMap"},
			{render.NodeTLSSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
			{render.TyphaTLSSecretName, common.OperatorNamespace(), "", "v1", "Secret"},
			{render.ManagerInternalTLSSecretName, common.OperatorNamespace(), "", "v1", "Secret"},

			// Typha objects.
			{render.TyphaServiceAccountName, common.CalicoNamespace, "", "v1", "ServiceAccount"},
			{common.TyphaDeploymentName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{common.TyphaDeploymentName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{render.TyphaServiceName, common.CalicoNamespace, "", "v1", "Service"},
			{common.TyphaDeploymentName, common.CalicoNamespace, "policy", "v1beta1", "PodDisruptionBudget"},
			{render.TyphaTLSSecretName, common.CalicoNamespace, "", "v1", "Secret"},
			{common.TyphaDeploymentName, "", "policy", "v1beta1", "PodSecurityPolicy"},
			{common.TyphaDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment"},

			// Node objects.
			{common.NodeDaemonSetName, common.CalicoNamespace, "", "v1", "ServiceAccount"},
			{common.NodeDaemonSetName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{common.NodeDaemonSetName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{render.TyphaCAConfigMapName, common.CalicoNamespace, "", "v1", "ConfigMap"},
			{render.NodeTLSSecretName, common.CalicoNamespace, "", "v1", "Secret"},
			{"calico-node-metrics", common.CalicoNamespace, "", "v1", "Service"},
			{"cni-config", common.CalicoNamespace, "", "v1", "ConfigMap"},
			{common.NodeDaemonSetName, "", "policy", "v1beta1", "PodSecurityPolicy"},
			{common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet"},

			// Kube-controllers objects.
			{common.KubeControllersDeploymentName, common.CalicoNamespace, "", "v1", "ServiceAccount"},
			{common.KubeControllersDeploymentName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{common.KubeControllersDeploymentName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{common.KubeControllersDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment"},
			{render.ManagerInternalTLSSecretName, common.CalicoNamespace, "", "v1", "Secret"},
			{common.KubeControllersDeploymentName, "", "policy", "v1beta1", "PodSecurityPolicy"},
			{"calico-kube-controllers-metrics", common.CalicoNamespace, "", "v1", "Service"},
		}

		var resources []client.Object
		for _, component := range c {
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
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, apparmorProf, dns.DefaultClusterDomain, 0, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
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
		bgpLayout.Namespace = common.OperatorNamespace()
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 0, 0, bgpLayout, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
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
		testNode := func(processPath operatorv1.CollectProcessPathOption, expectedHostPID bool) {
			var logCollector operatorv1.LogCollector
			logCollector.Spec.CollectProcessPath = &processPath
			comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, &logCollector)
			Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
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
		testNode(operatorv1.CollectProcessPathEnable, true)
		testNode(operatorv1.CollectProcessPathDisable, false)
	})

	It("should set node priority class to system-node-critical", func() {
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cn *appsv1.DaemonSet
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
			if r != nil {
				cn = r.(*appsv1.DaemonSet)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.Spec.PriorityClassName).To(Equal("system-node-critical"))
	})

	It("should set typha priority class to system-cluster-critical", func() {
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cn *appsv1.Deployment
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, common.TyphaDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment")
			if r != nil {
				cn = r.(*appsv1.Deployment)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.Spec.PriorityClassName).To(Equal("system-cluster-critical"))
	})

	It("should set kube controllers priority class to system-cluster-critical", func() {
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, operatorv1.ProviderNone, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cn *appsv1.Deployment
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, common.KubeControllersDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment")
			if r != nil {
				cn = r.(*appsv1.Deployment)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.Spec.PriorityClassName).To(Equal("system-cluster-critical"))
	})
})

func componentCount(components []render.Component) int {
	count := 0
	for _, c := range components {
		objsToCreate, _ := c.Objects()
		count += len(objsToCreate)
		glog.Printf("Component: %s\n", reflect.TypeOf(c))
		for i, o := range objsToCreate {
			glog.Printf(" - %d/%d: %s/%s\n", i, len(objsToCreate), o.GetNamespace(), o.GetName())
		}
	}
	return count
}
