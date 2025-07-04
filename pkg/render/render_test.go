// Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const clusterDomain = "cluster.local"

// allCalicoComponents takes the given configuration and returns all the components
// associated with installing Calico's core, similar to how the core_controller behaves.
func allCalicoComponents(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operatorv1.InstallationSpec,
	managementCluster *operatorv1.ManagementCluster,
	managementClusterConnection *operatorv1.ManagementClusterConnection,
	pullSecrets []*corev1.Secret,
	typhaNodeTLS *render.TyphaNodeTLS,
	managerInternalTLSSecret certificatemanagement.KeyPairInterface,
	bt map[string]string,
	up bool,
	nodeAppArmorProfile string,
	clusterDomain string,
	kubeControllersMetricsPort int,
	nodeReporterMetricsPort int,
	bgpLayout *corev1.ConfigMap,
	logCollector *operatorv1.LogCollector,
) ([]render.Component, error) {
	namespaces := render.Namespaces(&render.NamespaceConfiguration{Installation: cr, PullSecrets: pullSecrets})

	objs := []client.Object{}
	if bgpLayout != nil {
		objs = append(objs, bgpLayout)
	}
	secretsAndConfigMaps := render.NewPassthrough(objs...)

	nodeCfg := &render.NodeConfiguration{
		K8sServiceEp:            k8sServiceEp,
		Installation:            cr,
		TLS:                     typhaNodeTLS,
		NodeAppArmorProfile:     nodeAppArmorProfile,
		ClusterDomain:           clusterDomain,
		NodeReporterMetricsPort: nodeReporterMetricsPort,
		BGPLayouts:              bgpLayout,
		LogCollector:            logCollector,
		BirdTemplates:           bt,
		MigrateNamespaces:       up,
		FelixHealthPort:         9099,
	}
	typhaCfg := &render.TyphaConfiguration{
		K8sServiceEp:      k8sServiceEp,
		Installation:      cr,
		TLS:               typhaNodeTLS,
		ClusterDomain:     clusterDomain,
		MigrateNamespaces: up,
		FelixHealthPort:   9099,
	}
	kcCfg := &kubecontrollers.KubeControllersConfiguration{
		K8sServiceEp:                k8sServiceEp,
		Installation:                cr,
		ManagementCluster:           managementCluster,
		ManagementClusterConnection: managementClusterConnection,
		ClusterDomain:               clusterDomain,
		MetricsPort:                 kubeControllersMetricsPort,
		Namespace:                   common.CalicoNamespace,
		BindingNamespaces:           []string{common.CalicoNamespace},
	}

	winCfg := &render.WindowsConfiguration{
		K8sServiceEp:            k8sServiceEp,
		K8sDNSServers:           []string{},
		Installation:            cr,
		ClusterDomain:           clusterDomain,
		TLS:                     typhaNodeTLS,
		NodeReporterMetricsPort: nodeReporterMetricsPort,
		VXLANVNI:                4096,
	}

	nodeCertComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       common.CalicoNamespace,
		ServiceAccounts: []string{render.CalicoNodeObjectName, render.TyphaServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.NodeSecret, true, true),
			rcertificatemanagement.NewKeyPairOption(managerInternalTLSSecret, true, true),
			rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.TyphaSecret, true, true),
		},
		TrustedBundle: typhaNodeTLS.TrustedBundle,
	})

	return []render.Component{namespaces, secretsAndConfigMaps, render.Typha(typhaCfg), render.Node(nodeCfg), kubecontrollers.NewCalicoKubeControllers(kcCfg), render.Windows(winCfg), nodeCertComponent}, nil
}

var _ = Describe("Rendering tests", func() {
	var instance *operatorv1.InstallationSpec
	var logBuffer bytes.Buffer
	var logWriter *bufio.Writer
	var typhaNodeTLS *render.TyphaNodeTLS
	var internalManagerKeyPair certificatemanagement.KeyPairInterface
	logSeverity := operatorv1.LogLevelInfo
	logFileMaxSize := resource.MustParse("100Mi")
	var logFileMaxAgeDays uint32 = 30
	var logFileMaxCount uint32 = 10
	one := intstr.FromInt(1)
	miMode := operatorv1.MultiInterfaceModeNone
	k8sServiceEp := k8sapi.ServiceEndpoint{}
	defaultCNIConfDir, defaultCNIBinDir := "/etc/cni/net.d", "/opt/cni/bin"

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1.InstallationSpec{
			CNI: &operatorv1.CNISpec{
				Type: operatorv1.PluginCalico,
				IPAM: &operatorv1.IPAMSpec{
					Type: operatorv1.IPAMPluginCalico,
				},
				BinDir:  &defaultCNIBinDir,
				ConfDir: &defaultCNIConfDir,
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
			Logging: &operatorv1.Logging{
				CNI: &operatorv1.CNILogging{
					LogSeverity:       &logSeverity,
					LogFileMaxSize:    &logFileMaxSize,
					LogFileMaxAgeDays: &logFileMaxAgeDays,
					LogFileMaxCount:   &logFileMaxCount,
				},
			},
			WindowsNodes: &operatorv1.WindowsNodeSpec{
				CNIBinDir:    "/opt/cni/bin",
				CNIConfigDir: "/etc/cni/net.d",
				CNILogDir:    "/var/log/calico/cni",
			},
		}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())

		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		typhaNodeTLS = getTyphaNodeTLS(cli, certificateManager)
		internalManagerKeyPair, err = certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())

		logWriter = bufio.NewWriter(&logBuffer)
		render.SetTestLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(logWriter)))
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			logWriter.Flush()
			fmt.Printf("Logs:\n%s\n", logBuffer.String())
		}
	})

	It("should render IfNotPresent image pull policy", func() {
		// This test ensures we don't accidentally commit a change that switches the
		// default image pull policy to Always as part of development.
		Expect(render.ImagePullPolicy()).To(Equal(corev1.PullIfNotPresent))
	})

	It("should render all resources for a default configuration", func() {
		// For this scenario, we expect the basic resources
		// created by the controller without any optional ones. These include:
		// - 5 node resources (ServiceAccount, ClusterRole, Binding, ConfigMap, DaemonSet)
		// - 3 calico-cni-plugin resources (ServiceAccount, ClusterRole, ClusterRoleBinding)
		// - 4 secrets for Typha comms (2 in operator namespace and 2 in calico namespace)
		// - 1 ConfigMap for Typha comms (1 in calico namespace)
		// - 6 typha resources (Service, SA, Role, Binding, Deployment, PodDisruptionBudget)
		// - 6 kube-controllers resources (ServiceAccount, ClusterRole, Binding, Deployment, Service, Secret,RoleBinding)
		// - 1 namespace
		// - 2 Windows node resources (ConfigMap, DaemonSet)
		c, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c)).To(Equal(5 + 3 + 4 + 1 + 6 + 6 + 1 + 2))
	})

	It("should render all resources when variant is Tigera Secure", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure:
		// - X Same as default config
		// - 1 Service to expose calico/node metrics.
		// - 1 Service to expose Windows calico/node metrics.
		var nodeMetricsPort int32 = 9081
		instance.Variant = operatorv1.TigeraSecureEnterprise
		instance.NodeMetricsPort = &nodeMetricsPort
		c, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c)).To(Equal((5 + 3 + 4 + 1 + 6 + 6 + 1 + 2) + 1 + 1))
	})

	It("should render all resources when variant is Tigera Secure and Management Cluster", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure:
		// - X Same as default config for EE
		// - pass in InternalManagerTLSSecret
		var nodeMetricsPort int32 = 9081
		instance.Variant = operatorv1.TigeraSecureEnterprise
		instance.NodeMetricsPort = &nodeMetricsPort

		c, err := allCalicoComponents(k8sServiceEp, instance, &operatorv1.ManagementCluster{}, nil, nil, typhaNodeTLS, internalManagerKeyPair, nil, false, "", dns.DefaultClusterDomain, 9094, 0, nil, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)

		expectedResources := []client.Object{
			// Namespaces first.
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},

			// Typha objects.
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.TyphaServiceAccountName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: common.TyphaDeploymentName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: common.TyphaDeploymentName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.TyphaServiceName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: common.TyphaDeploymentName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: common.TyphaDeploymentName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},

			// Node objects.
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-cni-plugin", Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-cni-plugin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-cni-plugin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-metrics", Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cni-config", Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},

			// Kube-controllers objects.
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: common.KubeControllersDeploymentName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: common.KubeControllersDeploymentName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: common.KubeControllersDeploymentName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ManagedClustersWatchRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: common.KubeControllersDeploymentName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers-metrics", Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},

			// Windows node objects.
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.WindowsNodeMetricsService, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cni-config-windows", Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: common.WindowsDaemonSetName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},

			// Certificate Management objects
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.NodeTLSSecretName, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.NodeTLSSecretName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerInternalTLSSecretName, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerInternalTLSSecretName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TyphaTLSSecretName, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TyphaTLSSecretName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},

			// 	Tigera operator secret rolebinding
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: common.CalicoNamespace}},
		}

		var resources []client.Object
		for _, component := range c {
			toCreate, _ := component.Objects()
			resources = append(resources, toCreate...)
		}
		rtest.ExpectResources(resources, expectedResources)
	})

	It("should render calico with a apparmor profile if annotation is present in installation", func() {
		apparmorProf := "foobar"
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, apparmorProf, dns.DefaultClusterDomain, 0, 0, nil, nil)
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
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, "", dns.DefaultClusterDomain, 0, 0, bgpLayout, nil)
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
			comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, &logCollector)
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
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, nil)
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
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, nil)
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
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, nil, typhaNodeTLS, nil, nil, false, "", dns.DefaultClusterDomain, 0, 0, nil, nil)
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

func getTyphaNodeTLS(cli client.Client, certificateManager certificatemanager.CertificateManager) *render.TyphaNodeTLS {
	nodeKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
	Expect(err).NotTo(HaveOccurred())

	typhaKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
	Expect(err).NotTo(HaveOccurred())

	typhaNonClusterHostKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName+render.TyphaNonClusterHostSuffix, common.OperatorNamespace(), []string{render.FelixCommonName + render.TyphaNonClusterHostSuffix})
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(nodeKeyPair, typhaKeyPair)

	return &render.TyphaNodeTLS{
		TrustedBundle:             trustedBundle,
		TyphaSecret:               typhaKeyPair,
		TyphaSecretNonClusterHost: typhaNonClusterHostKeyPair,
		TyphaCommonName:           render.TyphaCommonName,
		NodeSecret:                nodeKeyPair,
		NodeCommonName:            render.FelixCommonName,
	}
}

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
