// Copyright (c) 2019, 2022-2023 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"

	operator "github.com/tigera/operator/api/v1"
)

var _ = Describe("Installation validation tests", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork:  &operator.CalicoNetworkSpec{},
				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: appsv1.RollingUpdateDaemonSetStrategyType,
				},
				Variant: operator.Calico,
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				ComponentResources:      []operator.ComponentResource{},
				KubeletVolumePluginPath: filepath.Clean("/var/lib/kubelet"),
			},
		}
	})

	It("should not allow blocksize to exceed the pool size", func() {
		// Try with an invalid block size.
		var twentySix int32 = 26
		var enabled operator.BGPOption = operator.BGPEnabled
		instance.Spec.CalicoNetwork.BGP = &enabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/27",
				BlockSize:     &twentySix,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())

		// Try with a valid block size
		instance.Spec.CalicoNetwork.IPPools[0].CIDR = "192.168.0.0/26"
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should prevent IPv6 if BPF is enabled", func() {
		bpf := operator.LinuxDataplaneBPF
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "1eef::/64",
				NATOutgoing:   operator.NATOutgoingEnabled,
				Encapsulation: operator.EncapsulationNone,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(MatchError("IPv6 IP pool is specified but eBPF mode does not support IPv6"))
	})

	It("should allow IPv6 VXLAN", func() {
		encaps := []operator.EncapsulationType{operator.EncapsulationVXLAN, operator.EncapsulationVXLANCrossSubnet}
		for _, vxlanMode := range encaps {
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "1eef::/64",
					NATOutgoing:   operator.NATOutgoingEnabled,
					Encapsulation: vxlanMode,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(BeNil())
		}
	})

	It("should prevent IPv6 if IPIP is enabled", func() {
		encaps := []operator.EncapsulationType{operator.EncapsulationIPIP, operator.EncapsulationIPIPCrossSubnet}
		for _, ipipMode := range encaps {
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "1eef::/64",
					NATOutgoing:   operator.NATOutgoingEnabled,
					Encapsulation: ipipMode,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(MatchError("IPIP encapsulation is not supported by IPv6 pools, but it is set for 1eef::/64"))
		}
	})

	It("should prevent multiple node address autodetection methods", func() {
		nodeIP := operator.NodeInternalIP
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			CanReach:   "8.8.8.8",
			Kubernetes: &nodeIP,
		}
		err := validateCustomResource(instance)
		Expect(err).To(MatchError("no more than one node address autodetection method can be specified per-family"))
	})

	It("should allow autodetection based on Kubernetes node IP", func() {
		nodeIP := operator.NodeInternalIP
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			Kubernetes: &nodeIP,
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should prevent host ports if BPF is enabled", func() {
		bpf := operator.LinuxDataplaneBPF
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		hp := operator.HostPortsEnabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			CanReach: "8.8.8.8",
		}
		err := validateCustomResource(instance)
		Expect(err).To(MatchError("spec.calicoNetwork.hostPorts is not supported with the eBPF dataplane"))
	})

	It("should allow disabled host ports if BPF is enabled", func() {
		bpf := operator.LinuxDataplaneBPF
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		hp := operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			CanReach: "8.8.8.8",
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow VPP to be used with a variant other than Calico", func() {
		vpp := operator.LinuxDataplaneVPP
		en := operator.BGPEnabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CalicoNetwork.BGP = &en
		instance.Spec.CNI.Type = operator.PluginCalico
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not allow VPP to be used with a CNI other than Calico", func() {
		vpp := operator.LinuxDataplaneVPP
		en := operator.BGPEnabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CalicoNetwork.BGP = &en
		instance.Spec.CNI.Type = operator.PluginAmazonVPC
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CNI.Type = operator.PluginCalico
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow VPP to be used if BGP is not enabled", func() {
		vpp := operator.LinuxDataplaneVPP
		en := operator.BGPEnabled
		dis := operator.BGPDisabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CNI.Type = operator.PluginCalico
		instance.Spec.CalicoNetwork.BGP = &dis
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.BGP = &en
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow HostPorts to be disabled with VPP", func() {
		vpp := operator.LinuxDataplaneVPP
		bgp := operator.BGPEnabled
		en := operator.HostPortsEnabled
		dis := operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CalicoNetwork.BGP = &bgp
		instance.Spec.CNI.Type = operator.PluginCalico
		instance.Spec.CalicoNetwork.HostPorts = &dis
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.HostPorts = &en
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should prevent IPIP if BGP is disabled", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationIPIP,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should prevent IPIP cross-subnet if BGP is disabled", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationIPIPCrossSubnet,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not error if CalicoNetwork is provided on EKS", func() {
		instance := &operator.Installation{}
		instance.Spec.CNI = &operator.CNISpec{Type: operator.PluginCalico}
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		instance.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
		instance.Spec.KubernetesProvider = operator.ProviderEKS

		// Fill in defaults and validate the result.
		Expect(fillDefaults(instance)).NotTo(HaveOccurred())
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should not allow out-of-bounds block sizes", func() {
		// Try with an invalid block size.
		var blockSizeTooBig int32 = 33
		var blockSizeTooSmall int32 = 19
		var blockSizeJustRight int32 = 32

		// Start with a valid block size - /32 - just on the border.
		var enabled operator.BGPOption = operator.BGPEnabled
		instance.Spec.CalicoNetwork.BGP = &enabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.0.0.0/8",
				BlockSize:     &blockSizeJustRight,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		// Try with out-of-bounds sizes now.
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooBig
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooSmall
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not allow a relative path in FlexVolumePath", func() {
		instance.Spec.FlexVolumePath = "foo/bar/baz"
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should allow arbitrary absolute path in KubeletVolumePluginPath", func() {
		instance.Spec.KubeletVolumePluginPath = "/some/abs/path"
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow a relative path in KubeletVolumePluginPath", func() {
		instance.Spec.KubeletVolumePluginPath = "relative/path"
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should allow 'None' value in KubeletVolumePluginPath", func() {
		instance.Spec.KubeletVolumePluginPath = "None"
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should validate controlPlaneNodeSelector", func() {
		instance.Spec.ControlPlaneNodeSelector = map[string]string{
			"kubernetes.io/os": "windows",
		}
		Expect(validateCustomResource(instance)).To(HaveOccurred())
	})

	It("should validate ControlPlaneReplicas", func() {
		var replicas int32

		replicas = -1
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).To(HaveOccurred())

		replicas = 0
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).To(HaveOccurred())

		replicas = 1
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())

		replicas = 2
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should validate HostPorts", func() {
		instance.Spec.CalicoNetwork.HostPorts = nil
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp := operator.HostPortsEnabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp = operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp = "NotValid"
		instance.Spec.CalicoNetwork.HostPorts = &hp
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not allow Calico to run in non-privileged mode if BPF is enabled", func() {
		np := operator.NonPrivilegedEnabled
		bpf := operator.LinuxDataplaneBPF
		instance.Spec.NonPrivileged = &np
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not allow Calico to run in non-privileged mode with Tigera Secure Enterprise", func() {
		np := operator.NonPrivilegedEnabled
		instance.Spec.NonPrivileged = &np
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	Describe("validate Calico CNI plugin Type", func() {
		DescribeTable("test invalid IPAM",
			func(ipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = operator.PluginCalico
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("valid IPAM values Calico,HostLocal"))
			},

			Entry("AmazonVPC", operator.IPAMPluginAmazonVPC),
			Entry("AzureVNET", operator.IPAMPluginAzureVNET),
		)
		DescribeTable("test valid IPAM",
			func(ipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = operator.PluginCalico
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			},

			Entry("Calico", operator.IPAMPluginCalico),
			Entry("HostLocal", operator.IPAMPluginHostLocal),
		)
		DescribeTable("with HostLocal IPAM",
			func(ipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = operator.PluginCalico
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			},

			Entry("Calico", operator.IPAMPluginCalico),
			Entry("HostLocal", operator.IPAMPluginHostLocal),
		)
		Describe("should validate HostLocal with IPPool", func() {
			BeforeEach(func() {
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: operator.IPAMPluginHostLocal}
				disabled := operator.BGPDisabled
				instance.Spec.CalicoNetwork.BGP = &disabled
			})
			It("with empty CalicoNetwork validates", func() {
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})

			It("with IPPool with Encapsulation None validates", func() {
				instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operator.EncapsulationNone,
						NATOutgoing:   operator.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})

			It("with BGP enabled validates", func() {
				enable := operator.BGPEnabled
				instance.Spec.CalicoNetwork.BGP = &enable
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})

			It("With dual-stack enabled", func() {
				instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operator.EncapsulationNone,
						NATOutgoing:   operator.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
					{
						CIDR:          "fe80:00::00/64",
						Encapsulation: operator.EncapsulationNone,
						NATOutgoing:   operator.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Describe("should validate CNILogging", func() {
			BeforeEach(func() {
				instance.Spec.Logging = &operator.Logging{
					CNI: &operator.CNILogging{},
				}
			})
			It("with nil LogSeverity", func() {
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogSeverity).To(Equal(operator.LogLevelInfo))
			})
			It("with nil LogFileMaxAgeDays", func() {
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogFileMaxAgeDays).To(Equal(uint32(30)))
			})
			It("with invalid LogFileMaxAgeDays", func() {
				instance.Spec.Logging.CNI.LogFileMaxAgeDays = new(uint32)
				*instance.Spec.Logging.CNI.LogFileMaxAgeDays = 0
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxAgeDays should be a positive non-zero integer"))
			})
			It("with nil LogFileMaxCount", func() {
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogFileMaxCount).To(Equal(uint32(10)))
			})
			It("with invalid LogFileMaxCount", func() {
				instance.Spec.Logging.CNI.LogFileMaxCount = new(uint32)
				*instance.Spec.Logging.CNI.LogFileMaxCount = 0
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.loggingConfig.cni.logFileMaxCount value should be greater than zero"))
			})
			It("with nil LogFileMaxSize", func() {
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogFileMaxSize).To(Equal(resource.MustParse("100Mi")))
			})
			It("with invalid LogFileMaxSize", func() {
				instance.Spec.Logging.CNI.LogFileMaxSize = new(resource.Quantity)
				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("1")
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))

				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("0")
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err = validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))

				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("-1")
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err = validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))

				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("1M")
				Expect(fillDefaults(instance)).NotTo(HaveOccurred())
				err = validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))
			})
		})
	})
	Describe("validate non-calico CNI plugin Type", func() {
		BeforeEach(func() {
			instance.Spec.CNI = &operator.CNISpec{}
		})
		It("should not allow empty CNI", func() {
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
		It("should not allow invalid CNI Type", func() {
			instance.Spec.CNI.Type = "bad"
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
		nonCalicoCNIEntries := []TableEntry{
			Entry("GKE", operator.PluginGKE, operator.IPAMPluginHostLocal),
			Entry("AmazonVPC", operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC),
			Entry("AzureVNET", operator.PluginAzureVNET, operator.IPAMPluginAzureVNET),
		}
		DescribeTable("test allowed plugins", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			Expect(fillDefaults(instance)).NotTo(HaveOccurred())
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries...)
		DescribeTable("test with no CalicoNetwork", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CalicoNetwork = nil
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries...)
		DescribeTable("test invalid CNI and IPAM combinations",
			func(plugin operator.CNIPluginType, allowedipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = plugin
				for _, x := range operator.IPAMPluginTypes {
					if allowedipam == x {
						continue
					}
					instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: x}
					err := validateCustomResource(instance)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("valid IPAM values " + allowedipam.String()))
				}
			},

			Entry("GKE", operator.PluginGKE, operator.IPAMPluginHostLocal),
			Entry("AmazonVPC", operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC),
			Entry("AzureVNET", operator.PluginAzureVNET, operator.IPAMPluginAzureVNET),
		)
		DescribeTable("should disallow Calico only fields",
			func(setField func(inst *operator.Installation)) {
				instance.Spec.CNI.Type = operator.PluginGKE
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: operator.IPAMPluginHostLocal}
				setField(instance)
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("supported only for Calico CNI"))
			},
			Entry("HostPorts", func(inst *operator.Installation) {
				hpe := operator.HostPortsEnabled
				inst.Spec.CalicoNetwork.HostPorts = &hpe
			}),
			Entry("MultiInterfaceMode", func(inst *operator.Installation) {
				mimm := operator.MultiInterfaceModeMultus
				inst.Spec.CalicoNetwork.MultiInterfaceMode = &mimm
			}),
			Entry("ContainerIPForwarding", func(inst *operator.Installation) {
				cipf := operator.ContainerIPForwardingEnabled
				inst.Spec.CalicoNetwork.ContainerIPForwarding = &cipf
			}),
		)
		DescribeTable("should allow IPPool", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationNone,
					NATOutgoing:   operator.NATOutgoingEnabled,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries...)
		DescribeTable("should disallow IPPool with IPIP", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationIPIP,
					NATOutgoing:   operator.NATOutgoingEnabled,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		}, nonCalicoCNIEntries...)
		DescribeTable("should disallow IPPool with non-all NodeSelector", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationIPIP,
					NATOutgoing:   operator.NATOutgoingEnabled,
					NodeSelector:  "anything()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		}, nonCalicoCNIEntries...)
		DescribeTable("should not allow BGP", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			be := operator.BGPEnabled
			instance.Spec.CalicoNetwork.BGP = &be
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries...)
	})
	Describe("cross validate CNI.Type and kubernetesProvider", func() {
		BeforeEach(func() {
			instance.Spec.CalicoNetwork = nil
			instance.Spec.CNI = &operator.CNISpec{}
		})
		DescribeTable("test allowed plugins",
			func(kubeProvider operator.Provider, plugin operator.CNIPluginType, ipam operator.IPAMPluginType, success bool) {
				instance.Spec.KubernetesProvider = kubeProvider
				instance.Spec.CNI.Type = plugin
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				if success {
					Expect(err).NotTo(HaveOccurred())
				} else {
					Expect(err).To(HaveOccurred())
				}
			},

			Entry("GKE plugin is not allowed on EKS", operator.ProviderEKS, operator.PluginGKE, operator.IPAMPluginHostLocal, false),
			Entry("AmazonVPC plugin is allowed on EKS", operator.ProviderEKS, operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC, true),
			Entry("AzureVNET plugin is not allowed on EKS", operator.ProviderEKS, operator.PluginAzureVNET, operator.IPAMPluginAzureVNET, false),
		)
	})
	Describe("validate ComponentResources", func() {
		It("should return nil when there are no ComponentResources to validate.", func() {
			Expect(validateCustomResource(instance)).To(BeNil())
		})

		It("should return nil when only supported ComponentNames are present.", func() {
			instance.Spec.ComponentResources = append(instance.Spec.ComponentResources, []operator.ComponentResource{
				{
					ComponentName: operator.ComponentNameTypha,
				},
				{
					ComponentName: operator.ComponentNameKubeControllers,
				},
				{
					ComponentName: operator.ComponentNameNode,
				},
			}...)
			Expect(validateCustomResource(instance)).To(BeNil())
		})

		It("should return an error when an invalid ComponentName is present", func() {
			instance.Spec.ComponentResources = append(instance.Spec.ComponentResources, operator.ComponentResource{
				ComponentName: "invalid-componentName",
			})
			Expect(validateCustomResource(instance)).ToNot(BeNil())
		})
	})

	It("validate custom installation", func() {
		disabled := operator.BGPDisabled
		ipfw := operator.ContainerIPForwardingEnabled
		var twentyEight int32 = 28
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				KubernetesProvider: operator.ProviderAKS,
				ImagePullSecrets:   []v1.LocalObjectReference{},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					BGP:                   &disabled,
					ContainerIPForwarding: &ipfw,
					IPPools: []operator.IPPool{
						{
							CIDR:          "192.168.0.0/27",
							BlockSize:     &twentyEight,
							Encapsulation: operator.EncapsulationNone,
						},
					},
				},
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginHostLocal},
				},
			},
		}
		Expect(fillDefaults(instance)).NotTo(HaveOccurred())
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("validate CalicoNodeDaemonSet", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CalicoNodeDaemonSet = &operator.CalicoNodeDaemonSet{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CalicoNodeDaemonSet = &operator.CalicoNodeDaemonSet{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CalicoNodeDaemonSet = &operator.CalicoNodeDaemonSet{
				Spec: &operator.CalicoNodeDaemonSetSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("validate CalicoKubeControllersDeployment", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CalicoKubeControllersDeployment = &operator.CalicoKubeControllersDeployment{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CalicoKubeControllersDeployment = &operator.CalicoKubeControllersDeployment{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CalicoKubeControllersDeployment = &operator.CalicoKubeControllersDeployment{
				Spec: &operator.CalicoKubeControllersDeploymentSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("validate TyphaDeployment", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.TyphaDeployment = &operator.TyphaDeployment{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.TyphaDeployment = &operator.TyphaDeployment{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.TyphaDeployment = &operator.TyphaDeployment{
				Spec: &operator.TyphaDeploymentSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("validate CalicoWindowsUpgradeDaemonSet", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CalicoWindowsUpgradeDaemonSet = &operator.CalicoWindowsUpgradeDaemonSet{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CalicoWindowsUpgradeDaemonSet = &operator.CalicoWindowsUpgradeDaemonSet{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CalicoWindowsUpgradeDaemonSet = &operator.CalicoWindowsUpgradeDaemonSet{
				Spec: &operator.CalicoWindowsUpgradeDaemonSetSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})
})
