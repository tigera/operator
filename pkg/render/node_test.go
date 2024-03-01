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

package render_test

import (
	"fmt"
	"net"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	tls2 "github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var (
	openshift            = true
	notOpenshift         = false
	bgpEnabled           = operatorv1.BGPEnabled
	bgpDisabled          = operatorv1.BGPDisabled
	nonPrivilegedEnabled = operatorv1.NonPrivilegedEnabled
	logSeverity          = operatorv1.LogLevelDebug
	logFileMaxAgeDays    = uint32(5)
	logFileMaxCount      = uint32(5)
	logFileMaxSize       = resource.MustParse("1Mi")
)

var _ = Describe("Node rendering tests", func() {
	type testConf struct {
		EnableIPv4 bool
		EnableIPv6 bool
	}
	for _, testConfig := range []testConf{
		{true, false},
		{false, true},
		{true, true},
	} {
		enableIPv4 := testConfig.EnableIPv4
		enableIPv6 := testConfig.EnableIPv6
		Describe(fmt.Sprintf("IPv4 enabled: %v, IPv6 enabled: %v", enableIPv4, enableIPv6), func() {
			var defaultInstance *operatorv1.InstallationSpec
			var typhaNodeTLS *render.TyphaNodeTLS
			var k8sServiceEp k8sapi.ServiceEndpoint
			one := intstr.FromInt(1)
			defaultNumExpectedResources := 9
			const defaultClusterDomain = "svc.cluster.local"
			var defaultMode int32 = 420
			var cfg render.NodeConfiguration
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
				if enableIPv4 {
					defaultInstance.CalicoNetwork.IPPools = append(defaultInstance.CalicoNetwork.IPPools, operatorv1.IPPool{CIDR: "192.168.1.0/16"})
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{FirstFound: &ff}
				}
				if enableIPv6 {
					defaultInstance.CalicoNetwork.IPPools = append(defaultInstance.CalicoNetwork.IPPools, operatorv1.IPPool{CIDR: "2001:db8:1::/122"})
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV6 = &operatorv1.NodeAddressAutodetection{FirstFound: &ff}
				}
				scheme := runtime.NewScheme()
				Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
				cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

				certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())

				// Create a dummy secret to pass as input.
				typhaNodeTLS = getTyphaNodeTLS(cli, certificateManager)

				// Dummy service endpoint for k8s API.
				k8sServiceEp = k8sapi.ServiceEndpoint{}

				// Create a default configuration.
				cfg = render.NodeConfiguration{
					K8sServiceEp:    k8sServiceEp,
					Installation:    defaultInstance,
					TLS:             typhaNodeTLS,
					ClusterDomain:   defaultClusterDomain,
					FelixHealthPort: 9099,
					UsePSP:          true,
				}
			})

			It("should render properly when PSP is not supported by the cluster", func() {
				cfg.UsePSP = false
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				// Should not contain any PodSecurityPolicies
				for _, r := range resources {
					Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
				}
			})

			It("should render all resources for a default configuration", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// Check CNI configmap.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)
				if enableIPv4 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")
				}
				if enableIPv6 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV6POOL_CIDR", "2001:db8:1::/122")
				}

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeTrue())
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				// Validate correct number of init containers.
				Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				// CNI container uses image override.
				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")
				Expect(cniContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

				Expect(*cniContainer.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*cniContainer.SecurityContext.Privileged).To(BeTrue())
				Expect(*cniContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*cniContainer.SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*cniContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(cniContainer.SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(cniContainer.SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				// Verify the Flex volume container image.
				flexvolContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")
				Expect(flexvolContainer.Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

				Expect(*flexvolContainer.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*flexvolContainer.SecurityContext.Privileged).To(BeTrue())
				Expect(*flexvolContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*flexvolContainer.SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*flexvolContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(flexvolContainer.SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(flexvolContainer.SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{
						Name: "CNI_NETWORK_CONFIG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key: "config",
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "cni-config",
								},
							},
						},
					},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

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
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should render node correctly for BPF dataplane", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				dpBPF := operatorv1.LinuxDataplaneBPF
				defaultInstance.CalicoNetwork.LinuxDataplane = &dpBPF
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
        "type": "calico-ipam",
        "assign_ipv4": "%t",
        "assign_ipv6": "%t"
      },
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "policy": {
        "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {
        "bandwidth": true
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)
				if enableIPv4 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")
				}
				if enableIPv6 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV6POOL_CIDR", "2001:db8:1::/122")
				}

				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

				// Node image override results in correct image.
				calicoNodeImage := fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(calicoNodeImage))

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(3))

				// CNI container uses image override.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

				// Verify the mount-bpffs image and command.
				mountBpffs := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "mount-bpffs")
				Expect(mountBpffs.Image).To(Equal(calicoNodeImage))
				Expect(mountBpffs.Command).To(Equal([]string{"calico-node", "-init"}))

				Expect(*mountBpffs.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*mountBpffs.SecurityContext.Privileged).To(BeTrue())
				Expect(*mountBpffs.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*mountBpffs.SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*mountBpffs.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(mountBpffs.SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(mountBpffs.SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{
						Name: "CNI_NETWORK_CONFIG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key: "config",
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "cni-config",
								},
							},
						},
					},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
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
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
					{MountPath: "/sys/fs/bpf", Name: "bpffs"},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should properly render an explicitly configured MTU", func() {
				mtu := int32(1450)
				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.CalicoNetwork.MTU = &mtu

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				// Make sure the configmap is populated correctly with the MTU.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 1450,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				// Make sure daemonset has the MTU set as well.
				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{}
				if enableIPv4 {
					expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
						{Name: "FELIX_IPINIPMTU", Value: "1450"},
						{Name: "FELIX_VXLANMTU", Value: "1450"},
						{Name: "FELIX_WIREGUARDMTU", Value: "1450"},
					}...)
				}
				if enableIPv6 {
					expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
						{Name: "FELIX_VXLANMTUV6", Value: "1450"},
						{Name: "FELIX_WIREGUARDMTUV6", Value: "1450"},
					}...)
				}
				for _, e := range expectedNodeEnv {
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(e))
				}
			})

			It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}
				defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
				cfg.NodeReporterMetricsPort = 9081

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node:" + components.ComponentTigeraNode.Version))
				rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/cni/net.d")

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, components.ComponentFlexVolumePrivate.Image, components.ComponentFlexVolumePrivate.Version)))

				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					// Tigera-specific envvars
					{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
					{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
					{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
					{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
					{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
					{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				verifyProbesAndLifecycle(ds, false, true)
			})

			It("should render all resources with the appropriate permissions when running as non-privileged", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.NonPrivileged = &nonPrivilegedEnabled
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct security context.
				ds := dsResource.(*appsv1.DaemonSet)
				nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "calico-node")
				Expect(nodeContainer).ToNot(BeNil())
				Expect(nodeContainer.SecurityContext).ToNot(BeNil())
				Expect(*nodeContainer.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*nodeContainer.SecurityContext.Privileged).To(BeFalse())
				Expect(*nodeContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*nodeContainer.SecurityContext.RunAsNonRoot).To(BeTrue())
				Expect(*nodeContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
				Expect(nodeContainer.SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{},
						Add: []corev1.Capability{
							"NET_ADMIN",
							"NET_BIND_SERVICE",
							"NET_RAW",
						},
					},
				))
				Expect(nodeContainer.SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				// hostpath init container should have the correct env and security context.
				hostPathContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "hostpath-init")
				rtest.ExpectEnv(hostPathContainer.Env, "NODE_USER_ID", "10001")
				Expect(*hostPathContainer.SecurityContext.RunAsUser).To(Equal(int64(0)))

				// Verify hostpath init container volume mounts.
				expectedHostPathInitVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/var/run", Name: "var-run"},
					{MountPath: "/var/lib", Name: "var-lib"},
					{MountPath: "/var/log", Name: "var-log"},
				}
				Expect(hostPathContainer.VolumeMounts).To(ConsistOf(expectedHostPathInitVolumeMounts))

				// Node image override results in correct image.
				calicoNodeImage := fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(calicoNodeImage))

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(3))

				// CNI container uses image override.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

				// Verify the mount-bpffs image and command.
				mountBpffs := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "mount-bpffs")
				Expect(mountBpffs).To(BeNil())

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}}},
					{Name: "var-lib", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib"}}},
					{Name: "var-log", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
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
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run", Name: "var-run"},
					{MountPath: "/var/lib", Name: "var-lib"},
					{MountPath: "/var/log", Name: "var-log"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))
			})

			It("should render all resources when using Calico CNI on EKS", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
				defaultInstance.CalicoNetwork.BGP = &bgpDisabled
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)
				if enableIPv4 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")
				}
				if enableIPv6 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV6POOL_CIDR", "2001:db8:1::/122")
				}

				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

				// CNI container uses image override.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

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
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{
						Name: "CNI_NETWORK_CONFIG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key: "config",
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "cni-config",
								},
							},
						},
					},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

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
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.

				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
				// Override the installation with one configured for AmazonVPC CNI.
				amazonVPCInstalllation := &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderEKS,
					CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
					FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				}
				cfg.Installation = amazonVPCInstalllation

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1))

				// Should render the correct resources.
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// Should not render CNI configuration.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).To(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// CNI install container should not be present.
				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				Expect(cniContainer).To(BeNil())

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

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
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
					{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
					{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},
					{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

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
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, true)
			})

			DescribeTable("should properly render configuration using non-Calico CNI plugin",
				func(cni operatorv1.CNIPluginType, ipam operatorv1.IPAMPluginType, expectedEnvs []corev1.EnvVar) {
					installlation := &operatorv1.InstallationSpec{
						CNI: &operatorv1.CNISpec{
							Type: cni,
							IPAM: &operatorv1.IPAMSpec{Type: ipam},
						},
						FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
					}
					cfg.Installation = installlation

					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()

					// Should render the correct resources.
					Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// Should not render CNI configuration.
					cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
					Expect(cniCmResource).To(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)

					// CNI install container should not be present.
					cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
					Expect(cniContainer).To(BeNil())
					// Validate correct number of init containers.
					Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

					// Verify env
					expectedEnvs = append(expectedEnvs,
						corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
						corev1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"},
						corev1.EnvVar{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					)
					for _, expected := range expectedEnvs {
						Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(expected))
					}

					// Verify readiness and liveness probes.
					verifyProbesAndLifecycle(ds, false, false)
				},
				Entry("GKE", operatorv1.PluginGKE, operatorv1.IPAMPluginHostLocal, []corev1.EnvVar{
					{Name: "FELIX_INTERFACEPREFIX", Value: "gke"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
					{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"},
				}),
				Entry("AmazonVPC", operatorv1.PluginAmazonVPC, operatorv1.IPAMPluginAmazonVPC, []corev1.EnvVar{
					{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
				}),
				Entry("AzureVNET", operatorv1.PluginAzureVNET, operatorv1.IPAMPluginAzureVNET, []corev1.EnvVar{
					{Name: "FELIX_INTERFACEPREFIX", Value: "azv"},
				}),
			)
			It("should render all resources when using Calico CNI on EKS", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				disabled := operatorv1.BGPDisabled
				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
				defaultInstance.CalicoNetwork.BGP = &disabled
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)
				if enableIPv4 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")
				}
				if enableIPv6 {
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV6POOL_CIDR", "2001:db8:1::/122")
				}

				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

				// CNI container uses image override.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

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
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{
						Name: "CNI_NETWORK_CONFIG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key: "config",
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "cni-config",
								},
							},
						},
					},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

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
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
				cfg.Installation = &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderEKS,
					CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
					FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				}

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1))

				// Should render the correct resources.
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// Should not render CNI configuration.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).To(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// CNI install container should not be present.
				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				Expect(cniContainer).To(BeNil())

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

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
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
					{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
					{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},
					{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

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
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should render all resources when running on openshift", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				cfg.FelixHealthPort = 9199
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// calico-node clusterRole should have openshift securitycontextconstraints PolicyRule
				nodeRole := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
				Expect(nodeRole.Rules).To(ContainElement(rbacv1.PolicyRule{
					APIGroups:     []string{"security.openshift.io"},
					Resources:     []string{"securitycontextconstraints"},
					Verbs:         []string{"use"},
					ResourceNames: []string{"privileged"},
				}))

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

				// Verify volumes. In particular, we want to make sure the flexvol-driver-host volume uses the right
				// host path for flexvolume drivers.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/cni/bin"}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/multus/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
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

				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9199"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				verifyProbesAndLifecycle(ds, true, false)
			})

			It("should render all resources when variant is TigeraSecureEnterprise and running on openshift", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				cfg.NodeReporterMetricsPort = 9081
				cfg.FelixHealthPort = 9199

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// calico-node clusterRole should have openshift securitycontextconstraints PolicyRule
				nodeRole := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
				Expect(nodeRole.Rules).To(ContainElement(rbacv1.PolicyRule{
					APIGroups:     []string{"security.openshift.io"},
					Resources:     []string{"securitycontextconstraints"},
					Verbs:         []string{"use"},
					ResourceNames: []string{"privileged"},
				}))

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node:" + components.ComponentTigeraNode.Version))

				rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, components.ComponentFlexVolumePrivate.Image, components.ComponentFlexVolumePrivate.Version)))

				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9199"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					// Tigera-specific envvars
					{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
					{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
					{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
					{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
					{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
					{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				verifyProbesAndLifecycle(ds, true, true)
			})

			It("should render all resources when variant is TigeraSecureEnterprise and running on RKE2", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
				defaultInstance.KubernetesProvider = operatorv1.ProviderRKE2
				cfg.NodeReporterMetricsPort = 9081
				cfg.FelixHealthPort = 9199

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)), fmt.Sprintf("Actual resources: %#v", resources))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node:" + components.ComponentTigeraNode.Version))

				rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/cni/net.d")

				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9199"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					// Tigera-specific envvars
					{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
					{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
					{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
					{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
					{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},

					// The RKE2 envvar overrides.
					{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				verifyProbesAndLifecycle(ds, true, true)

				// The metrics service should have the correct configuration.
				ms := rtest.GetResource(resources, "calico-node-metrics", "calico-system", "", "v1", "Service").(*corev1.Service)
				Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless to prevent kube-proxy from rendering too many iptables rules")
			})

			It("should render volumes and node volumemounts when bird templates are provided", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: render.BirdTemplatesConfigMapName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				cfg.BirdTemplates = map[string]string{
					"template-1.yaml": "dataforTemplate1 that is not used here",
				}
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				volumes := ds.Spec.Template.Spec.Volumes
				// Expect(ds.Spec.Template.Spec.Volumes).To(Equal())
				Expect(volumes).To(ContainElement(
					corev1.Volume{
						Name: "bird-templates",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "bird-templates",
								},
							},
						},
					}))

				volumeMounts := ds.Spec.Template.Spec.Containers[0].VolumeMounts
				Expect(volumeMounts).To(ContainElement(
					corev1.VolumeMount{
						Name:      "bird-templates",
						ReadOnly:  true,
						MountPath: "/etc/calico/confd/templates/template-1.yaml",
						SubPath:   "template-1.yaml",
					}))
			})
			Describe("AKS", func() {
				It("should avoid virtual nodes", func() {
					defaultInstance.KubernetesProvider = operatorv1.ProviderAKS
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					Expect(ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).To(ContainElement(
						corev1.NodeSelectorTerm{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "type",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{"virtual-kubelet"},
							}},
						},
					))
				})
			})
			Describe("EKS", func() {
				It("should avoid virtual fargate nodes", func() {
					defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					Expect(ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).To(ContainElement(
						corev1.NodeSelectorTerm{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "eks.amazonaws.com/compute-type",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{"fargate"},
							}},
						},
					))
				})
			})
			Describe("test IP auto detection", func() {
				It("should support canReach", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CanReach = "1.1.1.1"
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "can-reach=1.1.1.1")
				})

				It("should support interface regex", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.Interface = "eth*"
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "interface=eth*")
				})

				It("should support skip-interface regex", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface = "eth*"
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "skip-interface=eth*")
				})

				It("should support cidr", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CIDRS = []string{"10.0.1.0/24", "10.0.2.0/24"}
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "cidr=10.0.1.0/24,10.0.2.0/24")
				})
			})

			It("should include updates needed for the core upgrade", func() {
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				cfg.MigrateNamespaces = true
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				// +2 for temporary calico-node ClusterRole and ClusterRoleBinding during namespace migration
				Expect(len(resources)).To(Equal(defaultNumExpectedResources+2), fmt.Sprintf("resources are %v", resources))

				// Should render the correct resources.
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())

				crbResource := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
				Expect(crbResource).ToNot(BeNil())
				crb := crbResource.(*rbacv1.ClusterRoleBinding)
				Expect(crb.Subjects).To(ContainElement(
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "calico-node",
						Namespace: "kube-system",
					},
				))

				Expect(rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)
				ns := ds.Spec.Template.Spec.NodeSelector
				Expect(ns).To(HaveKey("projectcalico.org/operator-node-migration"))
				Expect(ns["projectcalico.org/operator-node-migration"]).To(Equal("migrated"))
			})

			trueValue := true
			falseValue := false
			DescribeTable("test IP Pool configuration",
				func(pool operatorv1.IPPool, expect map[string]string) {
					// Provider does not matter for IPPool configuration
					defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{pool}
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					nodeEnvs := ds.Spec.Template.Spec.Containers[0].Env

					for _, envVar := range []string{
						"CALICO_IPV4POOL_CIDR",
						"CALICO_IPV4POOL_IPIP",
						"CALICO_IPV4POOL_VXLAN",
						"CALICO_IPV4POOL_NAT_OUTGOING",
						"CALICO_IPV4POOL_NODE_SELECTOR",
						"CALICO_IPV4POOL_DISABLE_BGP_EXPORT",
						"CALICO_IPV6POOL_DISABLE_BGP_EXPORT",
					} {
						v, ok := expect[envVar]
						if ok {
							Expect(nodeEnvs).To(ContainElement(corev1.EnvVar{Name: envVar, Value: v}))
						} else {
							found := false
							for _, ev := range nodeEnvs {
								if ev.Name == envVar {
									found = true
									break
								}
							}
							Expect(found).To(BeFalse(), "Expected EnvVars %v to not have %s", nodeEnvs, envVar)
						}
					}
				},

				Entry("Default pool",
					operatorv1.IPPool{
						CIDR: "192.168.0.0/16",
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR": "192.168.0.0/16",
						"CALICO_IPV4POOL_IPIP": "Always",
					}),
				Entry("Pool with nat outgoing disabled",
					operatorv1.IPPool{
						CIDR:        "172.16.0.0/24",
						NATOutgoing: "Disabled",
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR":         "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP":         "Always",
						"CALICO_IPV4POOL_NAT_OUTGOING": "false",
					}),
				Entry("Pool with nat outgoing enabled",
					operatorv1.IPPool{
						CIDR:        "172.16.0.0/24",
						NATOutgoing: "Enabled",
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP": "Always",
						// Enabled is the default so we don't set
						// NAT_OUTGOING if it is enabled.
					}),
				Entry("Pool with VXLAN enabled (IPv6)",
					operatorv1.IPPool{
						CIDR:          "fc00::/48",
						Encapsulation: operatorv1.EncapsulationVXLAN,
					},
					map[string]string{
						"CALICO_IPV6POOL_CIDR":  "fc00::/48",
						"CALICO_IPV6POOL_VXLAN": "Always",
					}),
				Entry("Pool with VXLAN cross subnet enabled (IPv6)",
					operatorv1.IPPool{
						CIDR:          "fc00::/48",
						Encapsulation: operatorv1.EncapsulationVXLANCrossSubnet,
					},
					map[string]string{
						"CALICO_IPV6POOL_CIDR":  "fc00::/48",
						"CALICO_IPV6POOL_VXLAN": "CrossSubnet",
					}),
				Entry("Pool with nat outgoing disabled (IPv6)",
					operatorv1.IPPool{
						CIDR:        "fc00::/48",
						NATOutgoing: "Disabled",
					},
					map[string]string{
						"CALICO_IPV6POOL_CIDR": "fc00::/48",
						// Disabled is the default so we don't set
						// NAT_OUTGOING if it is disabled.
					}),
				Entry("Pool with nat outgoing enabled (IPv6)",
					operatorv1.IPPool{
						CIDR:        "fc00::/48",
						NATOutgoing: "Enabled",
					},
					map[string]string{
						"CALICO_IPV6POOL_CIDR":         "fc00::/48",
						"CALICO_IPV6POOL_NAT_OUTGOING": "true",
					}),
				Entry("Pool with CrossSubnet",
					operatorv1.IPPool{
						CIDR:          "172.16.0.0/24",
						Encapsulation: operatorv1.EncapsulationIPIPCrossSubnet,
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP": "CrossSubnet",
					}),
				Entry("Pool with VXLAN",
					operatorv1.IPPool{
						CIDR:          "172.16.0.0/24",
						Encapsulation: operatorv1.EncapsulationVXLAN,
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR":  "172.16.0.0/24",
						"CALICO_IPV4POOL_VXLAN": "Always",
					}),
				Entry("Pool with VXLANCrossSubnet",
					operatorv1.IPPool{
						CIDR:          "172.16.0.0/24",
						Encapsulation: operatorv1.EncapsulationVXLANCrossSubnet,
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR":  "172.16.0.0/24",
						"CALICO_IPV4POOL_VXLAN": "CrossSubnet",
					}),
				Entry("Pool with no encapsulation",
					operatorv1.IPPool{
						CIDR:          "172.16.0.0/24",
						Encapsulation: operatorv1.EncapsulationNone,
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP": "Never",
					}),
				Entry("Pool with node selector",
					operatorv1.IPPool{
						CIDR:         "172.16.0.0/24",
						NodeSelector: "has(thiskey)",
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR":          "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP":          "Always",
						"CALICO_IPV4POOL_NODE_SELECTOR": "has(thiskey)",
					}),
				Entry("Pool with v4 disable BGP export set to true",
					operatorv1.IPPool{
						CIDR:             "172.16.0.0/24",
						DisableBGPExport: &trueValue,
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR":               "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP":               "Always",
						"CALICO_IPV4POOL_DISABLE_BGP_EXPORT": "true",
					}),
				Entry("Pool with v4 disable BGP export set to false",
					operatorv1.IPPool{
						CIDR:             "172.16.0.0/24",
						DisableBGPExport: &falseValue,
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR":               "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP":               "Always",
						"CALICO_IPV4POOL_DISABLE_BGP_EXPORT": "false",
					}),
				Entry("Pool with v6 disable BGP export set to true",
					operatorv1.IPPool{
						CIDR:             "fc00::/48",
						DisableBGPExport: &trueValue,
					},
					map[string]string{
						"CALICO_IPV6POOL_CIDR":               "fc00::/48",
						"CALICO_IPV6POOL_IPIP":               "Always",
						"CALICO_IPV6POOL_DISABLE_BGP_EXPORT": "true",
					}),
				Entry("Pool with v6 disable BGP export set to false",
					operatorv1.IPPool{
						CIDR:             "fc00::/48",
						DisableBGPExport: &falseValue,
					},
					map[string]string{
						"CALICO_IPV6POOL_CIDR":               "fc00::/48",
						"CALICO_IPV6POOL_IPIP":               "Always",
						"CALICO_IPV6POOL_DISABLE_BGP_EXPORT": "false",
					}),
				Entry("Pool with all fields set",
					operatorv1.IPPool{
						CIDR:             "172.16.0.0/24",
						Encapsulation:    operatorv1.EncapsulationIPIP,
						NATOutgoing:      "Disabled",
						NodeSelector:     "has(thiskey)",
						DisableBGPExport: &trueValue,
					},
					map[string]string{
						"CALICO_IPV4POOL_CIDR":               "172.16.0.0/24",
						"CALICO_IPV4POOL_IPIP":               "Always",
						"CALICO_IPV4POOL_NAT_OUTGOING":       "false",
						"CALICO_IPV4POOL_NODE_SELECTOR":      "has(thiskey)",
						"CALICO_IPV4POOL_DISABLE_BGP_EXPORT": "true",
					}),
			)

			It("should not enable prometheus metrics if NodeMetricsPort is nil", func() {
				defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
				defaultInstance.NodeMetricsPort = nil
				cfg.NodeReporterMetricsPort = 9081

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				notExpectedEnvVar := corev1.EnvVar{Name: "FELIX_PROMETHEUSMETRICSPORT"}
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(notExpectedEnvVar))

				// It should have the reporter port, though.
				expected := corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT"}
				Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(expected))
			})

			It("should set FELIX_PROMETHEUSMETRICSPORT with a custom value if NodeMetricsPort is set", func() {
				var nodeMetricsPort int32 = 1234
				defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
				defaultInstance.NodeMetricsPort = &nodeMetricsPort
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// Assert on expected env vars.
				expectedEnvVars := []corev1.EnvVar{
					{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: "1234"},
					{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
				}
				ds := dsResource.(*appsv1.DaemonSet)
				for _, v := range expectedEnvVars {
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(v))
				}

				// Assert we set annotations properly.
				Expect(ds.Spec.Template.Annotations["prometheus.io/scrape"]).To(Equal("true"))
				Expect(ds.Spec.Template.Annotations["prometheus.io/port"]).To(Equal("1234"))
			})

			It("should not render a FlexVolume container if FlexVolumePath is set to None", func() {
				defaultInstance.FlexVolumePath = "None"
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")).To(BeNil())
			})

			It("should render MaxUnavailable if a custom value was set", func() {
				two := intstr.FromInt(2)
				defaultInstance.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &two
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())

				Expect(ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable).To(Equal(&two))
			})

			It("should render LinuxPolicySetupTimeoutSeconds if a custom value was set", func() {
				two := int32(2)
				defaultInstance.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &two
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())

				for _, c := range ds.Spec.Template.Spec.Containers {
					Expect(c.Env).To(ContainElement(corev1.EnvVar{
						Name:  "FELIX_ENDPOINTSTATUSPATHPREFIX",
						Value: "/var/run/calico",
					}))
				}
			})

			It("should render cni config without portmap when HostPorts disabled", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				hpd := operatorv1.HostPortsDisabled
				defaultInstance.CalicoNetwork.HostPorts = &hpd
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    }
  ]
}`, enableIPv4, enableIPv6)))

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{
						Name: "CNI_NETWORK_CONFIG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key: "config",
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "cni-config",
								},
							},
						},
					},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

				Expect(ds.Spec.Template.Spec.Volumes).To(ContainElement(
					corev1.Volume{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}}))

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))
			})

			It("should render cni config with sysctl parameters", func() {
				sysctl := []operatorv1.Sysctl{
					{
						Key:   "net.ipv4.tcp_keepalive_intvl",
						Value: "15",
					}, {
						Key:   "net.ipv4.tcp_keepalive_probes",
						Value: "6",
					},
					{
						Key:   "net.ipv4.tcp_keepalive_time",
						Value: "40",
					},
				}
				defaultInstance.CalicoNetwork.Sysctl = sysctl
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "datastore_type": "kubernetes",
        "ipam": {
          "assign_ipv4":  "%t",
          "assign_ipv6":  "%t",
          "type": "calico-ipam"
      },
      "kubernetes": {
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      },
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "log_file_max_size": 1,
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_level": "Debug",
      "mtu": 0,
      "nodename_file_optional": false,
      "policy": {
        "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "type": "calico"
    },
    {
      "capabilities": {
        "bandwidth": true
      },
      "type": "bandwidth"
    },
    {
      "capabilities": {
        "portMappings": true
      },
      "snat": true,
      "type": "portmap"
    },
    {
      "sysctl":
		  {
			"net.ipv4.tcp_keepalive_intvl": "15",
			"net.ipv4.tcp_keepalive_probes": "6",
			"net.ipv4.tcp_keepalive_time": "40"
		  },
      "type": "tuning"
	}
  ]
  }`, enableIPv4, enableIPv6)))
			})

			It("should render a proper 'policy_setup_timeout_seconds' setting in the cni config", func() {
				one := int32(1)
				defaultInstance.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &one
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy_setup_timeout_seconds": 1,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))
			})

			It("should render a proper 'allow_ip_forwarding' container setting in the cni config", func() {
				cif := operatorv1.ContainerIPForwardingEnabled
				defaultInstance.CalicoNetwork.ContainerIPForwarding = &cif
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": true
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))
			})

			It("should render cni config with host-local", func() {
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)

				// Assemble subnet JSON based on whether IPv4 and/or IPv6 are enabled
				var subnetStr string
				if enableIPv4 && enableIPv6 {
					subnetStr = `"ranges": [
                  [
                    {
                      "subnet": "usePodCidr"
                    }
                  ],
                  [
                    {
                      "subnet": "usePodCidrIPv6"
                    }
                  ]
                ]`
				} else if enableIPv4 {
					subnetStr = `"subnet" : "usePodCidr"`
				} else if enableIPv6 {
					subnetStr = `"subnet" : "usePodCidrIPv6"`
				}

				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          %s
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "container_settings": { "allow_ip_forwarding": false },
      "policy": { "type": "k8s" },
      "kubernetes": { "kubeconfig": "__KUBECONFIG_FILEPATH__" }
    },
    {"type": "bandwidth", "capabilities": {"bandwidth": true}},
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, subnetStr)))
			})

			It("should render cni config with host-local (dual-stack)", func() {
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operatorv1.EncapsulationNone,
						NATOutgoing:   operatorv1.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
					{
						CIDR:          "fe80:00::00/64",
						Encapsulation: operatorv1.EncapsulationNone,
						NATOutgoing:   operatorv1.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          "ranges": [[{"subnet": "usePodCidr"}], [{"subnet": "usePodCidrIPv6"}]]
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "container_settings": { "allow_ip_forwarding": false },
      "policy": { "type": "k8s" },
      "kubernetes": { "kubeconfig": "__KUBECONFIG_FILEPATH__" }
    },
    {"type": "bandwidth", "capabilities": {"bandwidth": true}},
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))
			})

			It("should render cni config with host-local (v6-only)", func() {
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{
					{
						CIDR:          "fe80:00::00/64",
						Encapsulation: operatorv1.EncapsulationNone,
						NATOutgoing:   operatorv1.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          "subnet" : "usePodCidrIPv6"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "container_settings": { "allow_ip_forwarding": false },
      "policy": { "type": "k8s" },
      "kubernetes": { "kubeconfig": "__KUBECONFIG_FILEPATH__" }
    },
    {"type": "bandwidth", "capabilities": {"bandwidth": true}},
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))
			})

			It("should render cni config with k8s endpoint", func() {
				k8sServiceEp.Host = "k8shost"
				k8sServiceEp.Port = "1234"
				cfg.K8sServiceEp = k8sServiceEp
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
        "type": "calico-ipam",
        "assign_ipv4" : "%t",
        "assign_ipv6" : "%t"
      },
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "policy": {
        "type": "k8s"
      },
      "kubernetes": {
        "k8s_api_root": "https://k8shost:1234",
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {
        "bandwidth": true
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}`, enableIPv4, enableIPv6)))
			})

			It("should render seccomp profiles", func() {
				seccompProf := "localhost/calico-node-v1"
				cfg.NodeAppArmorProfile = seccompProf
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())

				Expect(ds.Spec.Template.Annotations["container.apparmor.security.beta.kubernetes.io/calico-node"]).To(Equal(seccompProf))
			})

			It("should set TIGERA_*_SECURITY_GROUP variables when AmazonCloudIntegration is defined", func() {
				cfg.AmazonCloudIntegration = &operatorv1.AmazonCloudIntegration{
					Spec: operatorv1.AmazonCloudIntegrationSpec{
						NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
						PodSecurityGroupID:   "sg-podsgid",
					},
				}
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// Assert on expected env vars.
				expectedEnvVars := []corev1.EnvVar{
					{Name: "TIGERA_DEFAULT_SECURITY_GROUPS", Value: "sg-nodeid,sg-masterid"},
					{Name: "TIGERA_POD_SECURITY_GROUP", Value: "sg-podsgid"},
				}
				ds := dsResource.(*appsv1.DaemonSet)
				for _, v := range expectedEnvVars {
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(v))
				}
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

				defaultInstance.ComponentResources = []operatorv1.ComponentResource{
					{
						ComponentName:        operatorv1.ComponentNameNode,
						ResourceRequirements: rr,
					},
				}

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)

				passed := false
				for _, container := range ds.Spec.Template.Spec.Containers {
					if container.Name == "calico-node" {
						Expect(container.Resources).To(Equal(*rr))
						passed = true
					}
				}
				Expect(passed).To(Equal(true))
			})

			It("should render when configured to use cloud routes with host-local", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				disabled := operatorv1.BGPDisabled
				defaultInstance.CalicoNetwork.BGP = &disabled
				defaultInstance.CNI.Type = operatorv1.PluginCalico
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{{
					CIDR:          "192.168.1.0/16",
					Encapsulation: operatorv1.EncapsulationNone,
					NATOutgoing:   operatorv1.NATOutgoingEnabled,
				}}
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          "subnet": "usePodCidr"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)
				rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				// Validate correct number of init containers.
				Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

				// CNI container uses image override.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

				// Verify the Flex volume container image.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator"},
					{Name: "USE_POD_CIDR", Value: "true"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
					{Name: "FIPS_MODE_ENABLED", Value: "false"},
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
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{
						Name: "CNI_NETWORK_CONFIG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key: "config",
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "cni-config",
								},
							},
						},
					},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, false)
			})

			DescribeTable("test node probes",
				func(isOpenshift, isEnterprise bool, bgpOption operatorv1.BGPOption) {
					if isOpenshift {
						defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
						cfg.FelixHealthPort = 9199
					}

					if isEnterprise {
						defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
					}

					defaultInstance.CalicoNetwork.BGP = &bgpOption

					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					ds := dsResource.(*appsv1.DaemonSet)
					verifyProbesAndLifecycle(ds, isOpenshift, isEnterprise)
				},

				Entry("k8s Calico OS no BGP", false, false, operatorv1.BGPDisabled),
				Entry("k8s Calico OS w/ BGP", false, false, operatorv1.BGPEnabled),
				Entry("k8s Enterprise no BGP", false, true, operatorv1.BGPDisabled),
				Entry("k8s Enterprise w/ BGP", false, true, operatorv1.BGPEnabled),
				Entry("OCP Calico OS no BGP", true, false, operatorv1.BGPDisabled),
				Entry("OCP Calico OSS w/ BGP", true, false, operatorv1.BGPEnabled),
				Entry("OCP Enterprise no BGP", true, true, operatorv1.BGPDisabled),
				Entry("OCP Enterprise w/ BGP", true, true, operatorv1.BGPEnabled),
			)

			Context("With VPP dataplane", func() {
				It("should set cluster type correctly", func() {
					vpp := operatorv1.LinuxDataplaneVPP
					cfg.Installation.CalicoNetwork.LinuxDataplane = &vpp
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					ds := dsResource.(*appsv1.DaemonSet)

					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
						corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp,vpp"},
					))
				})
			})

			Context("with k8s overrides set", func() {
				It("should override k8s endpoints", func() {
					cfg.K8sServiceEp = k8sapi.ServiceEndpoint{
						Host: "k8shost",
						Port: "1234",
					}
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					ds := dsResource.(*appsv1.DaemonSet)

					// FIXME update gomega to include ContainElements
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
					))
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
					))

					var cni corev1.Container

					for _, c := range ds.Spec.Template.Spec.InitContainers {
						if c.Name == "install-cni" {
							cni = c
							break
						}
					}
					Expect(cni).NotTo(BeNil())

					Expect(cni.Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
					))
					Expect(cni.Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
					))
				})
			})

			It("should render extra resources when certificate management is enabled", func() {
				ca, _ := tls2.MakeCA(rmeta.DefaultOperatorCASignerName())
				cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
				cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cert}

				certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())

				cfg.TLS = getTyphaNodeTLS(cli, certificateManager)
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				component := render.Node(&cfg)
				resources, _ := component.Objects()

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}
				Expect(len(resources)).To(Equal(len(expectedResources)))

				dep := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
				Expect(dep).ToNot(BeNil())
				deploy, ok := dep.(*appsv1.DaemonSet)
				Expect(ok).To(BeTrue())
				Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(3))
				Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", render.NodeTLSSecretName)))
				Expect(deploy.Spec.Template.Spec.InitContainers[1].Name).To(Equal("flexvol-driver"))
				Expect(deploy.Spec.Template.Spec.InitContainers[2].Name).To(Equal("install-cni"))
				rtest.ExpectEnv(deploy.Spec.Template.Spec.InitContainers[0].Env, "SIGNER", "a.b/c")
			})

			It("should handle BGP layout", func() {
				cfg.BGPLayouts = &corev1.ConfigMap{Data: map[string]string{"test": "data"}}
				component := render.Node(&cfg)
				resources, _ := component.Objects()

				dep := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
				Expect(dep).ToNot(BeNil())
				deploy, ok := dep.(*appsv1.DaemonSet)
				Expect(ok).To(BeTrue())
				Expect(deploy.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/bgp-layout"))
				Expect(deploy.Spec.Template.Annotations["hash.operator.tigera.io/bgp-layout"]).To(Equal("46aec5c60cd6c6fc95979e247a8370bdb9f23b0f"))
				Expect(deploy.Spec.Template.Spec.Volumes).To(ContainElement(corev1.Volume{
					Name: render.BGPLayoutVolumeName,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: render.BGPLayoutConfigMapName,
							},
						},
					},
				}))
				Expect(deploy.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
					Name:      render.BGPLayoutVolumeName,
					ReadOnly:  true,
					MountPath: render.BGPLayoutPath,
					SubPath:   render.BGPLayoutConfigMapKey,
				}))
				rtest.ExpectEnv(deploy.Spec.Template.Spec.Containers[0].Env, "CALICO_EARLY_NETWORKING", render.BGPLayoutPath)
			})

			It("should render the correct env and/or images when FIPS mode is enabled (EE)", func() {
				fipsEnabled := operatorv1.FIPSModeEnabled
				cfg.Installation.FIPSMode = &fipsEnabled
				cfg.Installation.Variant = operatorv1.TigeraSecureEnterprise
				cfg.Installation.NodeMetricsPort = ptr.Int32ToPtr(123)

				certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())

				cfg.PrometheusServerTLS = certificateManager.KeyPair()
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())

				resources, _ := component.Objects()
				nodeDSObj := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
				Expect(nodeDSObj).ToNot(BeNil())

				nodeDS, ok := nodeDSObj.(*appsv1.DaemonSet)
				Expect(ok).To(BeTrue())

				Expect(nodeDS.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-node"))
				Expect(nodeDS.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "FIPS_MODE_ENABLED", Value: "true"}))

				Expect(nodeDS.Spec.Template.Spec.InitContainers[1].Name).To(Equal("install-cni"))
				Expect(nodeDS.Spec.Template.Spec.InitContainers[1].Image).To(ContainSubstring("-fips"))
			})

			It("should render the correct env and/or images when FIPS mode is enabled (OSS)", func() {
				fipsEnabled := operatorv1.FIPSModeEnabled
				cfg.Installation.FIPSMode = &fipsEnabled
				cfg.Installation.Variant = operatorv1.Calico
				cfg.Installation.NodeMetricsPort = ptr.Int32ToPtr(123)

				certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())

				cfg.PrometheusServerTLS = certificateManager.KeyPair()
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())

				resources, _ := component.Objects()
				nodeDSObj := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
				Expect(nodeDSObj).ToNot(BeNil())

				nodeDS, ok := nodeDSObj.(*appsv1.DaemonSet)
				Expect(ok).To(BeTrue())

				Expect(nodeDS.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-node"))
				Expect(nodeDS.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "FIPS_MODE_ENABLED", Value: "true"}))
				Expect(nodeDS.Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("-fips"))

				Expect(nodeDS.Spec.Template.Spec.InitContainers[1].Name).To(Equal("install-cni"))
				Expect(nodeDS.Spec.Template.Spec.InitContainers[1].Image).To(ContainSubstring("-fips"))
			})

			Context("With calico-node DaemonSet overrides", func() {
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

				It("should handle calicoNodeDaemonSet overrides", func() {
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

					defaultInstance.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"top-level": "label1"},
							Annotations: map[string]string{"top-level": "annot1"},
						},
						Spec: &operatorv1.CalicoNodeDaemonSetSpec{
							MinReadySeconds: &minReadySeconds,
							Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
								Metadata: &operatorv1.Metadata{
									Labels:      map[string]string{"template-level": "label2"},
									Annotations: map[string]string{"template-level": "annot2"},
								},
								Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
									Containers: []operatorv1.CalicoNodeDaemonSetContainer{
										{
											Name:      "calico-node",
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

					component := render.Node(&cfg)
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					ds := dsResource.(*appsv1.DaemonSet)

					Expect(ds.Labels).To(HaveLen(1))
					Expect(ds.Labels["top-level"]).To(Equal("label1"))
					Expect(ds.Annotations).To(HaveLen(1))
					Expect(ds.Annotations["top-level"]).To(Equal("annot1"))

					Expect(ds.Spec.MinReadySeconds).To(Equal(minReadySeconds))

					// At runtime, the operator will also add some standard labels to the
					// daemonset such as "k8s-app=calico-node". But the calico-node daemonset object
					// produced by the render will have no labels so we expect just the one
					// provided.
					Expect(ds.Spec.Template.Labels).To(HaveLen(1))
					Expect(ds.Spec.Template.Labels["template-level"]).To(Equal("label2"))

					// With the default instance we expect 3 template-level annotations
					// - 2 added by the operator by default
					// - 1 added by the calicoNodeDaemonSet override
					Expect(ds.Spec.Template.Annotations).To(HaveLen(3))
					Expect(ds.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
					Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/cni-config"))
					Expect(ds.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

					Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))

					Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

					Expect(ds.Spec.Template.Spec.Tolerations).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
				})

				It("should override ComponentResources", func() {
					defaultInstance.ComponentResources = []operatorv1.ComponentResource{
						{
							ComponentName:        operatorv1.ComponentNameNode,
							ResourceRequirements: &rr1,
						},
					}

					defaultInstance.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
						Spec: &operatorv1.CalicoNodeDaemonSetSpec{
							Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
								Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
									Containers: []operatorv1.CalicoNodeDaemonSetContainer{
										{
											Name:      "calico-node",
											Resources: &rr2,
										},
									},
								},
							},
						},
					}

					component := render.Node(&cfg)
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					ds := dsResource.(*appsv1.DaemonSet)
					Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr2))
				})
			})
		})
	}
})

// verifyProbesAndLifecycle asserts the expected node liveness and readiness probe plus pod lifecycle settings.
func verifyProbesAndLifecycle(ds *appsv1.DaemonSet, isOpenshift, isEnterprise bool) {
	// Verify readiness and liveness probes.
	expectedReadiness := &corev1.Probe{
		ProbeHandler:   corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}}},
		TimeoutSeconds: 10,
	}
	expectedLiveness := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: "localhost",
				Path: "/liveness",
				Port: intstr.FromInt(9099),
			},
		},
		TimeoutSeconds: 10,
	}

	if isOpenshift {
		expectedLiveness.HTTPGet.Port = intstr.FromInt(9199)
	}

	var found bool
	var bgp bool
	for _, env := range ds.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "CLUSTER_TYPE" {
			if strings.Contains(env.Value, ",bgp") {
				bgp = true
			}
			found = true
			break
		}
	}
	ExpectWithOffset(1, found).To(BeTrue())

	switch {
	case !bgp:
		expectedReadiness.Exec.Command = []string{"/bin/calico-node", "-felix-ready"}
	case bgp && !isEnterprise:
		expectedReadiness.Exec.Command = []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}
	case bgp && isEnterprise:
		expectedReadiness.Exec.Command = []string{"/bin/calico-node", "-bird-ready", "-felix-ready", "-bgp-metrics-ready"}
	}

	ExpectWithOffset(1, ds.Spec.Template.Spec.Containers[0].ReadinessProbe).To(Equal(expectedReadiness))
	ExpectWithOffset(1, ds.Spec.Template.Spec.Containers[0].LivenessProbe).To(Equal(expectedLiveness))

	expectedLifecycle := &corev1.Lifecycle{
		PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-shutdown"}}},
	}
	ExpectWithOffset(1, ds.Spec.Template.Spec.Containers[0].Lifecycle).To(Equal(expectedLifecycle))

	ExpectWithOffset(1, int(*ds.Spec.Template.Spec.TerminationGracePeriodSeconds)).To(Equal(5))
}

// configureExpectedNodeEnvIPVersions is a helper function to configure the right expected calico-node env var values based on if IPv4 and/or IPv6 are enabled
func configureExpectedNodeEnvIPVersions(expectedNodeEnv []corev1.EnvVar, defaultInstance *operatorv1.InstallationSpec, enableIPv4, enableIPv6 bool) []corev1.EnvVar {
	for _, pool := range defaultInstance.CalicoNetwork.IPPools {
		ip, _, err := net.ParseCIDR(pool.CIDR)
		Expect(err).NotTo(HaveOccurred())
		if ip.To4() != nil {
			expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_CIDR", Value: pool.CIDR})
			switch pool.Encapsulation {
			case operatorv1.EncapsulationIPIP:
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"})
			case operatorv1.EncapsulationIPIPCrossSubnet:
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "CrossSubnet"})
			case operatorv1.EncapsulationVXLAN:
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_VXLAN", Value: "Always"})
			case operatorv1.EncapsulationVXLANCrossSubnet:
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_VXLAN", Value: "CrossSubnet"})
			case operatorv1.EncapsulationNone:
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Never"})
			default:
				// IPIP is the default encapsulation
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"})
			}
		} else {
			expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
				{Name: "CALICO_IPV6POOL_CIDR", Value: pool.CIDR},
			}...)
			switch pool.Encapsulation {
			case operatorv1.EncapsulationVXLAN:
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_VXLAN", Value: "Always"})
			case operatorv1.EncapsulationVXLANCrossSubnet:
				expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_VXLAN", Value: "CrossSubnet"})
			}
		}
	}
	if enableIPv4 {
		expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
		}...)
	} else {
		expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "IP", Value: "none"})
	}

	if enableIPv6 {
		expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
			{Name: "FELIX_IPV6SUPPORT", Value: "true"},
			{Name: "IP6", Value: "autodetect"},
			{Name: "IP6_AUTODETECTION_METHOD", Value: "first-found"},
		}...)
		if !enableIPv4 && defaultInstance.CalicoNetwork.BGP == &bgpEnabled {
			expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_ROUTER_ID", Value: "hash"})
		}
	} else {
		expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "IP6", Value: "none"},
		}...)
	}

	return expectedNodeEnv
}
