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

package installation

import (
	"path/filepath"

	"k8s.io/apimachinery/pkg/api/resource"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	osconfigv1 "github.com/openshift/api/config/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Defaulting logic tests", func() {
	It("should properly fill defaults on an empty instance", func() {
		instance := &operator.Installation{}
		err := fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.Variant).To(Equal(operator.Calico))
		Expect(instance.Spec.Registry).To(BeEmpty())
		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v4pool).ToNot(BeNil())
		Expect(v4pool.CIDR).To(Equal("192.168.0.0/16"))
		Expect(v4pool.BlockSize).NotTo(BeNil())
		Expect(*v4pool.BlockSize).To(Equal(int32(26)))
		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v6pool).To(BeNil())
		Expect(instance.Spec.CNI.Type).To(Equal(operator.PluginCalico))
		Expect(instance.Spec.CalicoNetwork).NotTo(BeNil())
		Expect(instance.Spec.CalicoNetwork.LinuxDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.LinuxDataplane).To(Equal(operator.LinuxDataplaneIptables))
		Expect(instance.Spec.CalicoNetwork.WindowsDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.WindowsDataplane).To(Equal(operator.WindowsDataplaneDisabled))
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(*instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds).To(BeZero())
		Expect(*instance.Spec.ControlPlaneReplicas).To(Equal(int32(2)))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		Expect(instance.Spec.NonPrivileged).NotTo(BeNil())
		Expect(*instance.Spec.NonPrivileged).To(Equal(operator.NonPrivilegedDisabled))
		Expect(instance.Spec.KubeletVolumePluginPath).To(Equal(filepath.Clean("/var/lib/kubelet")))
		Expect(*instance.Spec.Logging.CNI.LogSeverity).To(Equal(operator.LogLevelInfo))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxCount).To(Equal(uint32(10)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxAgeDays).To(Equal(uint32(30)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxSize).To(Equal(resource.MustParse("100Mi")))
	})

	It("should properly fill defaults on an empty TigeraSecureEnterprise instance", func() {
		instance := &operator.Installation{}
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		err := fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.Variant).To(Equal(operator.TigeraSecureEnterprise))
		Expect(instance.Spec.Registry).To(BeEmpty())
		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v4pool).ToNot(BeNil())
		Expect(v4pool.CIDR).To(Equal("192.168.0.0/16"))
		Expect(v4pool.BlockSize).NotTo(BeNil())
		Expect(*v4pool.BlockSize).To(Equal(int32(26)))
		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v6pool).To(BeNil())
		Expect(instance.Spec.CalicoNetwork).NotTo(BeNil())
		Expect(instance.Spec.CalicoNetwork.LinuxDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.LinuxDataplane).To(Equal(operator.LinuxDataplaneIptables))
		Expect(instance.Spec.CalicoNetwork.WindowsDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.WindowsDataplane).To(Equal(operator.WindowsDataplaneDisabled))
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(*instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds).To(BeZero())
		Expect(*instance.Spec.ControlPlaneReplicas).To(Equal(int32(2)))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		Expect(instance.Spec.NonPrivileged).NotTo(BeNil())
		Expect(*instance.Spec.NonPrivileged).To(Equal(operator.NonPrivilegedDisabled))
		Expect(instance.Spec.KubeletVolumePluginPath).To(Equal(filepath.Clean("/var/lib/kubelet")))
	})

	It("should not override custom configuration", func() {
		var mtu int32 = 1500
		var nodeMetricsPort int32 = 9081
		false_ := false
		var twentySeven int32 = 27
		var oneTwoThree int32 = 123
		var one intstr.IntOrString = intstr.FromInt(1)
		var replicas int32 = 3
		var logFileMaxCount uint32 = 5
		var logFileMaxAgeDays uint32 = 10
		logFileMaxSize := resource.MustParse("50Mi")
		logSeverity := operator.LogLevelError
		var linuxPolicySetupTimeoutSeconds int32 = 1

		hpEnabled := operator.HostPortsEnabled
		disabled := operator.BGPDisabled
		miMode := operator.MultiInterfaceModeNone
		dpIptables := operator.LinuxDataplaneIptables
		winDataplaneDisabled := operator.WindowsDataplaneDisabled
		nonPrivileged := operator.NonPrivilegedEnabled
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Variant:       operator.Calico,
				NonPrivileged: &nonPrivileged,
				Registry:      "test-reg/",
				ImagePullSecrets: []v1.LocalObjectReference{
					{
						Name: "pullSecret1",
					},
					{
						Name: "pullSecret2",
					},
				},
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					LinuxDataplane:   &dpIptables, // Actually the default but BPF would make other values invalid.
					WindowsDataplane: &winDataplaneDisabled,
					IPPools: []operator.IPPool{
						{
							CIDR:          "1.2.3.0/24",
							Encapsulation: "VXLANCrossSubnet",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &twentySeven,
						},
						{
							CIDR:          "fd00::0/64",
							Encapsulation: "None",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &oneTwoThree,
						},
					},
					MTU: &mtu,
					BGP: &disabled,
					NodeAddressAutodetectionV4: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					NodeAddressAutodetectionV6: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					HostPorts:                      &hpEnabled,
					MultiInterfaceMode:             &miMode,
					LinuxPolicySetupTimeoutSeconds: &linuxPolicySetupTimeoutSeconds,
				},
				ControlPlaneReplicas: &replicas,
				NodeMetricsPort:      &nodeMetricsPort,
				FlexVolumePath:       "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: appsv1.RollingUpdateDaemonSetStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &one,
					},
				},
				KubeletVolumePluginPath: "/my/kubelet/root/dir",
				Logging: &operator.Logging{
					CNI: &operator.CNILogging{
						LogSeverity:       &logSeverity,
						LogFileMaxSize:    &logFileMaxSize,
						LogFileMaxAgeDays: &logFileMaxAgeDays,
						LogFileMaxCount:   &logFileMaxCount,
					},
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operator.Installation)
		err := fillDefaults(instanceCopy)
		Expect(err).NotTo(HaveOccurred())
		Expect(instanceCopy.Spec).To(Equal(instance.Spec))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should not override custom configuration (BPF)", func() {
		var mtu int32 = 1500
		var nodeMetricsPort int32 = 9081
		false_ := false
		var twentySeven int32 = 27
		var one intstr.IntOrString = intstr.FromInt(1)
		var replicas int32 = 3
		var logFileMaxCount uint32 = 5
		var logFileMaxAgeDays uint32 = 10
		logFileMaxSize := resource.MustParse("50Mi")
		logSeverity := operator.LogLevelError

		disabled := operator.BGPDisabled
		miMode := operator.MultiInterfaceModeNone
		dpBPF := operator.LinuxDataplaneBPF
		winDataplaneDisabled := operator.WindowsDataplaneDisabled
		hpEnabled := operator.HostPortsEnabled
		npDisabled := operator.NonPrivilegedDisabled
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Variant:       operator.TigeraSecureEnterprise,
				NonPrivileged: &npDisabled,
				Registry:      "test-reg/",
				ImagePullSecrets: []v1.LocalObjectReference{
					{
						Name: "pullSecret1",
					},
					{
						Name: "pullSecret2",
					},
				},
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					LinuxDataplane:   &dpBPF, // Actually the default but BPF would make other values invalid.
					WindowsDataplane: &winDataplaneDisabled,
					IPPools: []operator.IPPool{
						{
							CIDR:          "1.2.3.0/24",
							Encapsulation: "VXLANCrossSubnet",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &twentySeven,
						},
					},
					MTU: &mtu,
					BGP: &disabled,
					NodeAddressAutodetectionV4: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					MultiInterfaceMode: &miMode,
					HostPorts:          &hpEnabled,
				},
				ControlPlaneReplicas: &replicas,
				NodeMetricsPort:      &nodeMetricsPort,
				FlexVolumePath:       "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: appsv1.RollingUpdateDaemonSetStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &one,
					},
				},
				KubeletVolumePluginPath: "/my/kubelet/root/dir",
				Logging: &operator.Logging{
					CNI: &operator.CNILogging{
						LogSeverity:       &logSeverity,
						LogFileMaxSize:    &logFileMaxSize,
						LogFileMaxAgeDays: &logFileMaxAgeDays,
						LogFileMaxCount:   &logFileMaxCount,
					},
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operator.Installation)
		err := fillDefaults(instanceCopy)
		Expect(err).NotTo(HaveOccurred())
		Expect(instanceCopy.Spec).To(Equal(instance.Spec))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should allow for zero IP pools to be specified", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{},
				},
			},
		}
		err := fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(instance.Spec.CalicoNetwork.IPPools)).To(Equal(0))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should default BGP to enabled for Calico CNI", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
				},
			},
		}
		err := fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should default BGP to disabled for other CNI plugins", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginAmazonVPC,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{},
			},
		}
		err := fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))

		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should correct missing slashes on registry", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Registry: "test-reg",
			},
		}
		err := fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.Registry).To(Equal("test-reg/"))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())

		// But "UseDefault" should not be modified.
		instance.Spec.Registry = components.UseDefault
		err = fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.Registry).To(Equal(components.UseDefault))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should properly fill defaults for an IPv6-only instance", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{{CIDR: "fd00::0/64"}},
				},
			},
		}

		err := fillDefaults(instance)
		Expect(err).NotTo(HaveOccurred())

		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v4pool).To(BeNil())

		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v6pool).NotTo(BeNil())
		Expect(v6pool.CIDR).To(Equal("fd00::0/64"))
		Expect(v6pool.BlockSize).NotTo(BeNil())
		Expect(*v6pool.BlockSize).To(Equal(int32(122)))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	table.DescribeTable("All pools should have all fields set from mergeAndFillDefaults function",
		func(i *operator.Installation, on *osconfigv1.Network, kadmc *v1.ConfigMap, awsN *appsv1.DaemonSet) {
			Expect(mergeAndFillDefaults(i, on, kadmc, nil)).To(BeNil())

			if i.Spec.CalicoNetwork != nil && i.Spec.CalicoNetwork.IPPools != nil && len(i.Spec.CalicoNetwork.IPPools) != 0 {
				v4pool := render.GetIPv4Pool(i.Spec.CalicoNetwork.IPPools)
				Expect(v4pool).ToNot(BeNil())
				Expect(v4pool.CIDR).ToNot(BeEmpty(), "CIDR should be set on pool %v", v4pool)
				Expect(v4pool.Encapsulation).To(BeElementOf(operator.EncapsulationTypes), "Encapsulation should be set on pool %q", v4pool)
				Expect(v4pool.NATOutgoing).To(BeElementOf(operator.NATOutgoingTypes), "NATOutgoing should be set on pool %v", v4pool)
				Expect(v4pool.NodeSelector).ToNot(BeEmpty(), "NodeSelector should be set on pool %v", v4pool)
				v6pool := render.GetIPv6Pool(i.Spec.CalicoNetwork.IPPools)
				Expect(v6pool).To(BeNil())
			}
			Expect(validateCustomResource(i)).NotTo(HaveOccurred())
		},

		table.Entry("Empty config defaults IPPool", &operator.Installation{}, nil, nil, nil),
		table.Entry("Openshift only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil, nil,
		),
		table.Entry("CIDR specified from OS config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{CIDR: "10.0.0.0/24"},
						},
					},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil, nil,
		),
		table.Entry("kubeadm only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			},
			nil,
			&v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 10.0.0.0/8"}},
			nil,
		),
		table.Entry("CIDR specified from kubeadm config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{CIDR: "10.0.0.0/24"},
						},
					},
				},
			},
			nil,
			&v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 10.0.0.0/8"}},
			nil,
		),
		table.Entry("CNI Type set from AWS Node daemonset and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			},
			nil, nil,
			&appsv1.DaemonSet{},
		),
	)

	table.DescribeTable("Test different values for FlexVolumePath",
		func(i *operator.Installation, expectedFlexVolumePath string) {
			Expect(fillDefaults(i)).To(BeNil())
			Expect(i.Spec.FlexVolumePath).To(Equal(expectedFlexVolumePath))
		},

		table.Entry("FlexVolumePath set to None",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					FlexVolumePath: "None",
				},
			}, "None",
		),

		table.Entry("FlexVolumePath left empty (default)",
			&operator.Installation{
				Spec: operator.InstallationSpec{},
			}, "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
		),

		table.Entry("FlexVolumePath set to a custom path",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					FlexVolumePath: "/foo/bar/",
				},
			}, "/foo/bar/",
		),
	)
	table.DescribeTable("Test different values for KubeletVolumePluginPath",
		func(i *operator.Installation, expectedKubeletVolumePluginPath string) {
			Expect(fillDefaults(i)).To(BeNil())
			Expect(i.Spec.KubeletVolumePluginPath).To(Equal(expectedKubeletVolumePluginPath))
		},

		table.Entry("KubeletVolumePluginPath set to None",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					KubeletVolumePluginPath: "None",
				},
			}, "None",
		),

		table.Entry("KubeletVolumePluginPath left empty (default)",
			&operator.Installation{
				Spec: operator.InstallationSpec{},
			}, filepath.Clean("/var/lib/kubelet"),
		),

		table.Entry("KubeletVolumePluginPath set to a custom path",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					KubeletVolumePluginPath: "/foo/bar/",
				},
			}, "/foo/bar/",
		),
	)
	It("should default an empty CNI to Calico with no KubernetesProvider", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{},
			},
		}
		Expect(fillDefaults(instance)).NotTo(HaveOccurred())
		Expect(instance.Spec.CNI.Type).To(Equal(operator.PluginCalico))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})
	It("should set default values for CNILogging if CNI is set to Calico", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{},
			},
		}
		Expect(fillDefaults(instance)).NotTo(HaveOccurred())
		Expect(*instance.Spec.Logging.CNI.LogSeverity).To(Equal(operator.LogLevelInfo))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxCount).To(Equal(uint32(10)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxAgeDays).To(Equal(uint32(30)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxSize).To(Equal(resource.MustParse("100Mi")))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})
	table.DescribeTable("should default CNI type based on KubernetesProvider for hosted providers",
		func(provider operator.Provider, plugin operator.CNIPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{KubernetesProvider: provider},
			}
			Expect(fillDefaults(instance)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.Type).To(Equal(plugin))
			iptables := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			bgpDisabled := operator.BGPDisabled
			Expect(instance.Spec.CalicoNetwork).To(Equal(&operator.CalicoNetworkSpec{
				LinuxDataplane:   &iptables,
				WindowsDataplane: &winDataplane,
				BGP:              &bgpDisabled,
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		},

		table.Entry("EKS provider defaults to AmazonVPC plugin", operator.ProviderEKS, operator.PluginAmazonVPC),
		table.Entry("GKE provider defaults to GKE plugin", operator.ProviderGKE, operator.PluginGKE),
		table.Entry("AKS provider defaults to AzureVNET plugin", operator.ProviderAKS, operator.PluginAzureVNET),
	)
	table.DescribeTable("setting non-Calico CNI Plugin should default CalicoNetwork to nil",
		func(plugin operator.CNIPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{Type: plugin},
				},
			}
			Expect(fillDefaults(instance)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.Type).To(Equal(plugin))
			iptables := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			bgpDisabled := operator.BGPDisabled
			Expect(instance.Spec.CalicoNetwork).To(Equal(&operator.CalicoNetworkSpec{
				LinuxDataplane:   &iptables,
				WindowsDataplane: &winDataplane,
				BGP:              &bgpDisabled,
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		},

		table.Entry("AmazonVPC plugin", operator.PluginAmazonVPC),
		table.Entry("GKE plugin", operator.PluginGKE),
		table.Entry("AzureVNET plugin", operator.PluginAzureVNET),
	)

	// Tests for Calico Networking on EKS should go in this context.
	Context("with Calico Networking on EKS", func() {
		It("should default properly", func() {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginCalico,
					},
				},
			}
			err := fillDefaults(instance)
			Expect(err).NotTo(HaveOccurred())
			Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))
			Expect(instance.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operator.EncapsulationVXLAN))
			Expect(instance.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("172.16.0.0/16"))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})
	})

	Context("with AmazonVPC CNI", func() {
		It("should default properly with no calicoNetwork specified", func() {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			}
			err := fillDefaults(instance)
			Expect(err).NotTo(HaveOccurred())
			iptables := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			bgpDisabled := operator.BGPDisabled
			Expect(instance.Spec.CalicoNetwork).To(Equal(&operator.CalicoNetworkSpec{
				LinuxDataplane:   &iptables,
				WindowsDataplane: &winDataplane,
				BGP:              &bgpDisabled,
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})

		It("should default properly with iptables explicitly enabled", func() {
			dpIpt := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CalicoNetwork: &operator.CalicoNetworkSpec{
						LinuxDataplane:   &dpIpt,
						WindowsDataplane: &winDataplane,
					},
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			}
			err := fillDefaults(instance)
			Expect(err).NotTo(HaveOccurred())
			Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))
			Expect(instance.Spec.CalicoNetwork.IPPools).To(BeEmpty())
			Expect(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4).To(BeNil())
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})

		It("should default properly with BPF enabled", func() {
			dpBPF := operator.LinuxDataplaneBPF
			winDataplane := operator.WindowsDataplaneDisabled
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CalicoNetwork: &operator.CalicoNetworkSpec{
						LinuxDataplane:   &dpBPF,
						WindowsDataplane: &winDataplane,
					},
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			}
			err := fillDefaults(instance)
			Expect(err).NotTo(HaveOccurred())
			Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))
			Expect(instance.Spec.CalicoNetwork.IPPools).To(BeEmpty())
			Expect(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4).To(Equal(&operator.NodeAddressAutodetection{
				CanReach: "8.8.8.8",
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})
	})

	table.DescribeTable("should default IPAM type based on CNI type",
		func(cni operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{Type: cni},
				},
			}
			Expect(fillDefaults(instance)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.IPAM.Type).To(Equal(ipam))
		},

		table.Entry("AmazonVPC CNI defaults to AmazonVPC IPAM", operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC),
		table.Entry("GKE CNI defaults to HostLocal IPAM", operator.PluginGKE, operator.IPAMPluginHostLocal),
		table.Entry("AzureVNET CNI defaults to AzureVNET IPAM", operator.PluginAzureVNET, operator.IPAMPluginAzureVNET),
		table.Entry("Calico CNI defaults to Calico IPAM", operator.PluginCalico, operator.IPAMPluginCalico),
	)
})
