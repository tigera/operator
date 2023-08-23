// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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
	// . "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Windows rendering tests", func() {
	var defaultInstance *operatorv1.InstallationSpec
	var typhaNodeTLS *render.TyphaNodeTLS
	var k8sServiceEp k8sapi.ServiceEndpoint
	one := intstr.FromInt(1)
	defaultNumExpectedResources := 8
	const defaultClusterDomain = "svc.cluster.local"
	var defaultMode int32 = 420
	var cfg render.WindowsConfiguration
	var cli client.Client

	BeforeEach(func() {
		ff := true
		hp := operatorv1.HostPortsEnabled
		miMode := operatorv1.MultiInterfaceModeNone
		defaultInstance = &operatorv1.InstallationSpec{
			CNI: &operatorv1.CNISpec{
				Type: "Calico",
				IPAM: &operatorv1.IPAMSpec{Type: "Calico"},
			},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{
				BGP:                        &bgpEnabled,
				IPPools:                    []operatorv1.IPPool{},
				NodeAddressAutodetectionV4: &operatorv1.NodeAddressAutodetection{},
				NodeAddressAutodetectionV6: &operatorv1.NodeAddressAutodetection{},
				HostPorts:                  &hp,
				MultiInterfaceMode:         &miMode,
			},
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
		}
		defaultInstance.CalicoNetwork.IPPools = append(defaultInstance.CalicoNetwork.IPPools, operatorv1.IPPool{CIDR: "192.168.1.0/16", Encapsulation: operatorv1.EncapsulationVXLAN})
		defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{FirstFound: &ff}
		defaultInstance.ServiceCIDRs = []string{"10.96.0.0/12"}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		// Create a dummy secret to pass as input.
		typhaNodeTLS = getTyphaNodeTLS(cli, certificateManager)

		// Dummy service endpoint for k8s API.
		k8sServiceEp = k8sapi.ServiceEndpoint{
			Host: "1.2.3.4",
			Port: "6443",
		}

		// Create a default configuration.
		cfg = render.WindowsConfiguration{
			K8sServiceEp:  k8sServiceEp,
			K8sDNSServers: []string{"10.96.0.10"},
			Installation:  defaultInstance,
			ClusterDomain: defaultClusterDomain,
			TLS:           typhaNodeTLS,
			VXLANVNI:      4096,
		}
	})

	It("should render all resources for a default configuration", func() {
		type testConf struct {
			EnableBGP   bool
			EnableVXLAN bool
		}
		for _, testConfig := range []testConf{
			{true, false},
			{false, true},
			{true, true},
		} {
			enableBGP := testConfig.EnableBGP
			enableVXLAN := testConfig.EnableVXLAN

			if enableBGP {
				defaultInstance.CalicoNetwork.BGP = &bgpEnabled
			} else {
				defaultInstance.CalicoNetwork.BGP = &bgpDisabled
			}

			if enableVXLAN {
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
			} else {
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationNone
			}
			Context(fmt.Sprintf("BGP enabled: %v, VXLAN enabled: %v", enableBGP, enableVXLAN), func() {

				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				component := render.Windows(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// Check CNI configmap.
				cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				mode := "none"
				if enableBGP {
					mode = "windows-bgp"
				} else if enableVXLAN {
					mode = "vxlan"
				}
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
"name": "Calico",
"cniVersion": "0.3.1",
"plugins": [
  {
	"DNS": {
      "Nameservers": [
	    "10.96.0.10"
	  ],
	  "Search": [
		"svc.cluster.local"
	  ]
	},
	"capabilities": {
	  "dns": true
	},
	"datastore_type": "kubernetes",
	"ipam": {
	  "subnet": "usePodCidr",
	  "type": "calico-ipam"
	},
	"kubernetes": {
	  "k8s_api_root": "https://1.2.3.4:6443",
	  "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
	},
	"log_file_max_age": 5,
	"log_file_max_count": 5,
	"log_file_max_size": 1,
	"log_file_path": "c:/var/log/calico/cni/cni.log",
	"log_level": "Debug",
	"mode": "%s",
	"mtu": 0,
	"name": "Calico",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"nodename_file": "__NODENAME_FILE__",
	"nodename_file_optional": true,
	"policies": [
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "ExceptionList": [
			"10.96.0.0/12"
		  ],
		  "Type": "OutBoundNAT"
		}
	  },
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "DestinationPrefix": "10.96.0.0/12",
		  "NeedEncap": true,
		  "Type": "SDNROUTE"
		}
	  }
	],
	"policy": {
	  "type": "k8s"
	},
	"type": "calico",
	"vxlan_mac_prefix": "0E-2A",
	"vxlan_vni": 4096,
	"windows_loopback_DSR": "__DSR_SUPPORT__",
	"windows_use_single_network": true
  }
]
}`, mode)))

				dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The calico-node-windows daemonset has 3 containers (felix, node and confd).
				// confd is only instantiated if using BGP.
				numContainers := 3
				if !enableBGP {
					numContainers = 2
				}
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(numContainers))
				for _, container := range ds.Spec.Template.Spec.Containers {
					rtest.ExpectEnv(container.Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

					// Windows node image override results in correct image.
					Expect(container.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
					Expect(container.SecurityContext.Capabilities).To(BeNil())
					Expect(container.SecurityContext.Privileged).To(BeNil())
					Expect(container.SecurityContext.SELinuxOptions).To(BeNil())
					Expect(container.SecurityContext.WindowsOptions).To(Not(BeNil()))
					Expect(container.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
					Expect(container.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
					Expect(*container.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
					Expect(*container.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
					Expect(container.SecurityContext.RunAsUser).To(BeNil())
					Expect(container.SecurityContext.RunAsGroup).To(BeNil())
					Expect(container.SecurityContext.RunAsNonRoot).To(BeNil())
					Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
					Expect(container.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
					Expect(container.SecurityContext.ProcMount).To(BeNil())
					Expect(container.SecurityContext.SeccompProfile).To(BeNil())
				}

				felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
				rtest.ExpectEnv(felixContainer.Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

				// Windows node image override results in correct image.
				Expect(felixContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
				Expect(felixContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(felixContainer.SecurityContext.Privileged).To(BeNil())
				Expect(felixContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(felixContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(felixContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(felixContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*felixContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*felixContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(felixContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(felixContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(felixContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(felixContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(felixContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(felixContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(felixContainer.SecurityContext.SeccompProfile).To(BeNil())

				nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
				rtest.ExpectEnv(nodeContainer.Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

				// Windows node image override results in correct image.
				Expect(nodeContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
				Expect(nodeContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(nodeContainer.SecurityContext.Privileged).To(BeNil())
				Expect(nodeContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(nodeContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(nodeContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(nodeContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*nodeContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*nodeContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(nodeContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(nodeContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(nodeContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(nodeContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(nodeContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(nodeContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(nodeContainer.SecurityContext.SeccompProfile).To(BeNil())

				if enableBGP {
					confdContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd")
					rtest.ExpectEnv(confdContainer.Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

					// Windows node image override results in correct image.
					Expect(confdContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
					Expect(confdContainer.SecurityContext.Capabilities).To(BeNil())
					Expect(confdContainer.SecurityContext.Privileged).To(BeNil())
					Expect(confdContainer.SecurityContext.SELinuxOptions).To(BeNil())
					Expect(confdContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
					Expect(confdContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
					Expect(confdContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
					Expect(*confdContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
					Expect(*confdContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
					Expect(confdContainer.SecurityContext.RunAsUser).To(BeNil())
					Expect(confdContainer.SecurityContext.RunAsGroup).To(BeNil())
					Expect(confdContainer.SecurityContext.RunAsNonRoot).To(BeNil())
					Expect(confdContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
					Expect(confdContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
					Expect(confdContainer.SecurityContext.ProcMount).To(BeNil())
					Expect(confdContainer.SecurityContext.SeccompProfile).To(BeNil())
				}

				// Validate correct number of init containers.
				Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				// CNI container uses image override.
				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")
				Expect(cniContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNIWindows.Image, components.ComponentCalicoCNIWindows.Version)))

				Expect(cniContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(cniContainer.SecurityContext.Privileged).To(BeNil())
				Expect(cniContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(cniContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(cniContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(cniContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*cniContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*cniContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(cniContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(cniContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(cniContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(cniContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(cniContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(cniContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(cniContainer.SecurityContext.SeccompProfile).To(BeNil())

				// uninstall container uses image override.
				uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
				Expect(uninstallContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))

				Expect(uninstallContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(uninstallContainer.SecurityContext.Privileged).To(BeNil())
				Expect(uninstallContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(uninstallContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(uninstallContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(uninstallContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*uninstallContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*uninstallContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(uninstallContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(uninstallContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(uninstallContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(uninstallContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(uninstallContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(uninstallContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(uninstallContainer.SecurityContext.SeccompProfile).To(BeNil())

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{
						Name: "NODENAME",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
						},
					},
					{
						Name: "NAMESPACE",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
						},
					},
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT" + certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT/node-certs/tls.key"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},

					{Name: "VXLAN_VNI", Value: "4096"},
					{Name: "VXLAN_ADAPTER", Value: ""},
					{Name: "KUBE_NETWORK", Value: "Calico.*"},
					{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
					{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
					{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
					{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
				}

				// Set CALICO_NETWORKING_BACKEND
				if enableBGP {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "windows-bgp"})
				} else if enableVXLAN {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"})
				} else {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
				}

				// Set CLUSTER_TYPE
				if enableBGP {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"})
				} else {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator"})
				}

				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, true, false)

				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).To(ConsistOf(expectedNodeEnv))
				}

				// Expect the SECURITY_GROUP env variables to not be set
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				}

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{Name: "VXLAN_VNI", Value: "4096"},
					{
						Name:  "KUBERNETES_NODE_NAME",
						Value: "",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
						},
					},
					{
						Name: "CNI_NETWORK_CONFIG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key: "config",
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "cni-config-windows",
								},
							},
						},
					},

					{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
					{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
					{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
					{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

				expectedUninstallEnv := []corev1.EnvVar{
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "CNI_NET_DIR", Value: "/host/etc/cni/net.d"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").Env).To(ConsistOf(expectedUninstallEnv))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "c:/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "c:/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				}

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

				expectedUninstallVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				expectedLiveness := &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-felix-live"}}},
					InitialDelaySeconds: 10,
					FailureThreshold:    6,
					TimeoutSeconds:      10,
					PeriodSeconds:       10,
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").LivenessProbe).To(Equal(expectedLiveness))

				expectedReadiness := &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-felix-ready"}}},
					TimeoutSeconds: 10,
					PeriodSeconds:  10,
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").ReadinessProbe).To(Equal(expectedReadiness))

				expectedLifecycle := &corev1.Lifecycle{
					PreStop: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-shutdown"}}},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Lifecycle).To(Equal(expectedLifecycle))
			})
		}
	})
	It("should properly render an explicitly configured MTU", func() {
		mtu := int32(1450)
		defaultInstance.CalicoNetwork.MTU = &mtu

		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Make sure the configmap is populated correctly with the MTU.
		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
"name": "Calico",
"cniVersion": "0.3.1",
"plugins": [
  {
	"DNS": {
      "Nameservers": [
	    "10.96.0.10"
	  ],
	  "Search": [
		"svc.cluster.local"
	  ]
	},
	"capabilities": {
	  "dns": true
	},
	"datastore_type": "kubernetes",
	"ipam": {
	  "subnet": "usePodCidr",
	  "type": "calico-ipam"
	},
	"kubernetes": {
	  "k8s_api_root": "https://1.2.3.4:6443",
	  "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
	},
	"log_file_max_age": 5,
	"log_file_max_count": 5,
	"log_file_max_size": 1,
	"log_file_path": "c:/var/log/calico/cni/cni.log",
	"log_level": "Debug",
	"mode": "windows-bgp",
	"mtu": 1450,
	"name": "Calico",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"nodename_file": "__NODENAME_FILE__",
	"nodename_file_optional": true,
	"policies": [
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "ExceptionList": [
			"10.96.0.0/12"
		  ],
		  "Type": "OutBoundNAT"
		}
	  },
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "DestinationPrefix": "10.96.0.0/12",
		  "NeedEncap": true,
		  "Type": "SDNROUTE"
		}
	  }
	],
	"policy": {
	  "type": "k8s"
	},
	"type": "calico",
	"vxlan_mac_prefix": "0E-2A",
	"vxlan_vni": 4096,
	"windows_loopback_DSR": "__DSR_SUPPORT__",
	"windows_use_single_network": true
  }
]
}`))

		// Make sure daemonset has the MTU set as well.
		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "FELIX_VXLANMTU", Value: "1450"},
			{Name: "FELIX_WIREGUARDMTU", Value: "1450"},
		}
		for _, e := range expectedNodeEnv {
			Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ContainElement(e))
			Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ContainElement(e))
			Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).To(ContainElement(e))
		}
	})

	It("should render all resources when using Calico CNI on EKS", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-cni-plugin-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-cni-plugin-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-cni-plugin-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
		defaultInstance.CalicoNetwork.BGP = &bgpDisabled
		defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
"name": "Calico",
"cniVersion": "0.3.1",
"plugins": [
  {
    "DNS": {
      "Nameservers": [
	    "10.96.0.10"
	  ],
      "Search": [
        "svc.cluster.local"
      ]
    },
    "capabilities": {
      "dns": true
    },
    "datastore_type": "kubernetes",
    "ipam": {
      "subnet": "usePodCidr",
      "type": "calico-ipam"
    },
    "kubernetes": {
      "k8s_api_root": "https://1.2.3.4:6443",
      "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
    },
    "log_file_max_age": 5,
    "log_file_max_count": 5,
    "log_file_max_size": 1,
    "log_file_path": "c:/var/log/calico/cni/cni.log",
    "log_level": "Debug",
    "mode": "vxlan",
    "mtu": 0,
    "name": "Calico",
    "nodename": "__KUBERNETES_NODE_NAME__",
    "nodename_file": "__NODENAME_FILE__",
    "nodename_file_optional": true,
    "policies": [
      {
      "Name": "EndpointPolicy",
      "Value": {
        "ExceptionList": [
          "10.96.0.0/12"
        ],
        "Type": "OutBoundNAT"
      }
      },
      {
      "Name": "EndpointPolicy",
      "Value": {
        "DestinationPrefix": "10.96.0.0/12",
        "NeedEncap": true,
        "Type": "SDNROUTE"
      }
      }
    ],
    "policy": {
      "type": "k8s"
    },
    "type": "calico",
    "vxlan_mac_prefix": "0E-2A",
    "vxlan_vni": 4096,
    "windows_loopback_DSR": "__DSR_SUPPORT__",
    "windows_use_single_network": true
  }
]
}`))

		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*appsv1.DaemonSet)

		// The calico-node-windows daemonset has 2 containers (felix, node) when using VXLAN
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(2))

		for _, container := range ds.Spec.Template.Spec.Containers {
			rtest.ExpectEnv(container.Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

			// Windows image override results in correct image.
			Expect(container.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
		}

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// CNI container uses image override.
		Expect(cniContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNIWindows.Image, components.ComponentCalicoCNIWindows.Version)))

		// uninstall container uses image override.
		uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
		Expect(uninstallContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT" + certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT/node-certs/tls.crt"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT/node-certs/tls.key"},
			{Name: "FIPS_MODE_ENABLED", Value: "false"},

			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "vpc.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
			{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
			{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
		}
		expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, true, false)

		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{Name: "VXLAN_VNI", Value: "4096"},

			{
				Name:  "KUBERNETES_NODE_NAME",
				Value: "",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "cni-config-windows",
						},
					},
				},
			},

			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
			{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
			{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		expectedUninstallEnv := []corev1.EnvVar{
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "CNI_NET_DIR", Value: "/host/etc/cni/net.d"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").Env).To(ConsistOf(expectedUninstallEnv))

		// Verify volumes.
		fileOrCreate := corev1.HostPathFileOrCreate
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-ca-bundle",
						},
					},
				},
			},
			{
				Name: render.NodeTLSSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "c:/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
			{MountPath: "c:/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		expectedUninstallVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		expectedLiveness := &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-felix-live"}}},
			InitialDelaySeconds: 10,
			FailureThreshold:    6,
			TimeoutSeconds:      10,
			PeriodSeconds:       10,
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").LivenessProbe).To(Equal(expectedLiveness))

		expectedReadiness := &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-felix-ready"}}},
			TimeoutSeconds: 10,
			PeriodSeconds:  10,
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").ReadinessProbe).To(Equal(expectedReadiness))

		expectedLifecycle := &corev1.Lifecycle{
			PreStop: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-shutdown"}}},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Lifecycle).To(Equal(expectedLifecycle))
	})

	It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
		// Override the installation with one configured for AmazonVPC CNI.
		amazonVPCInstalllation := &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
			CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
			// FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
			ServiceCIDRs: []string{"10.96.0.0/12"},
		}
		cfg.Installation = amazonVPCInstalllation

		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1)) //TODO: ?

		// Should render the correct resources.
		Expect(rtest.GetResource(resources, "calico-node-windows", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node-windows", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node-windows", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Should not render CNI configuration.
		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).To(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*appsv1.DaemonSet)

		// CNI install container should not be present.
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer).To(BeNil())

		// uninstall container should still be present.
		uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
		Expect(uninstallContainer).NotTo(BeNil())

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "IP", Value: "none"},
			{Name: "IP6", Value: "none"},
			{Name: "NO_DEFAULT_POOLS", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "false"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT" + certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT/node-certs/tls.crt"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "$env:CONTAINER_SANDBOX_MOUNT_POINT/node-certs/tls.key"},
			{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
			{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},
			{Name: "FIPS_MODE_ENABLED", Value: "false"},

			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "vpc.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
			{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
			{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
		}

		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		// Verify volumes.
		fileOrCreate := corev1.HostPathFileOrCreate
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-ca-bundle",
						},
					},
				},
			},
			{
				Name: render.NodeTLSSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "c:/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
			{MountPath: "c:/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		expectedLiveness := &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-felix-live"}}},
			InitialDelaySeconds: 10,
			FailureThreshold:    6,
			TimeoutSeconds:      10,
			PeriodSeconds:       10,
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").LivenessProbe).To(Equal(expectedLiveness))

		expectedReadiness := &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-felix-ready"}}},
			TimeoutSeconds: 10,
			PeriodSeconds:  10,
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").ReadinessProbe).To(Equal(expectedReadiness))

		expectedLifecycle := &corev1.Lifecycle{
			PreStop: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico-node.exe", "-shutdown"}}},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Lifecycle).To(Equal(expectedLifecycle))
	})
})
