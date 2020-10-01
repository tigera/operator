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

package installation

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
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

	It("should validate controlPlaneNodeSelector", func() {
		instance.Spec.ControlPlaneNodeSelector = map[string]string{
			"kubernetes.io/os": "windows",
		}
		Expect(validateCustomResource(instance)).To(HaveOccurred())
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
})
