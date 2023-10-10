// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
)

var _ = Describe("AdrianaNode rendering tests", func() {

	enableIPv4 := true
	enableIPv6 := true
	Describe(fmt.Sprintf("IPv4 enabled: %v, IPv6 enabled: %v", enableIPv4, enableIPv6), func() {
		var defaultInstance *operatorv1.InstallationSpec
		var typhaNodeTLS *render.TyphaNodeTLS
		var k8sServiceEp k8sapi.ServiceEndpoint
		one := intstr.FromInt(1)
		//defaultNumExpectedResources := 9
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
			cli = fake.NewClientBuilder().WithScheme(scheme).Build()

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
			_ = cfg
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
				rtest.CompareResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
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
			Expect(ds.Annotations[render.BpfOperatorAnnotation]).To(Equal("true"))

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

			sum := 6
			//Expect(err).NotTo(HaveOccurred())
			Expect(sum).To(Equal(6))
		})
	})

})
