// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

package utils

import (
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	diff "github.com/r3labs/diff/v2"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	opv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/test"
)

func intPtr(i int32) *int32 { return &i }

var _ = Describe("Installation merge tests", func() {
	DescribeTable("merge Variant", func(main, second, expectVariant *opv1.ProductVariant) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.Variant = *main
		}
		if second != nil {
			s.Variant = *second
		}
		inst := OverrideInstallationSpec(m, s)
		if expectVariant == nil {
			var x opv1.ProductVariant
			Expect(inst.Variant).To(Equal(x))
		} else {
			Expect(inst.Variant).To(Equal(*expectVariant))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &opv1.Calico, nil, &opv1.Calico),
		Entry("Second only set", nil, &opv1.Calico, &opv1.Calico),
		Entry("Both set equal", &opv1.Calico, &opv1.Calico, &opv1.Calico),
		Entry("Both set not matching", &opv1.Calico, &opv1.TigeraSecureEnterprise, &opv1.TigeraSecureEnterprise),
	)

	DescribeTable("merge Registry", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.Registry = main
		}
		if second != "" {
			s.Registry = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.Registry).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "private.registry.com", nil, "private.registry.com"),
		Entry("Second only set", nil, "private.registry.com", "private.registry.com"),
		Entry("Both set equal", "private.registry.com", "private.registry.com", "private.registry.com"),
		Entry("Both set not matching", "private.registry.com", "other.registry.com", "other.registry.com"),
	)

	DescribeTable("merge ImagePath", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.ImagePath = main
		}
		if second != "" {
			s.ImagePath = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.ImagePath).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "pathx", nil, "pathx"),
		Entry("Second only set", nil, "pathx", "pathx"),
		Entry("Both set equal", "pathx", "pathx", "pathx"),
		Entry("Both set not matching", "pathx", "pathy", "pathy"),
	)

	DescribeTable("merge imagePullSecrets", func(main, second, expect []v1.LocalObjectReference) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.ImagePullSecrets = main
		}
		if second != nil {
			s.ImagePullSecrets = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.ImagePullSecrets).To(ConsistOf(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", []v1.LocalObjectReference{{Name: "pull-secret"}}, nil, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Second only set", nil, []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Both set equal", []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Both set not matching", []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "other-pull-secret"}}, []v1.LocalObjectReference{{Name: "other-pull-secret"}}),
	)

	DescribeTable("merge KubernetesProvider", func(main, second, expect *opv1.Provider) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.KubernetesProvider = *main
		}
		if second != nil {
			s.KubernetesProvider = *second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			var x opv1.Provider
			Expect(inst.KubernetesProvider).To(Equal(x))
		} else {
			Expect(inst.KubernetesProvider).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &opv1.ProviderGKE, nil, &opv1.ProviderGKE),
		Entry("Second only set", nil, &opv1.ProviderAKS, &opv1.ProviderAKS),
		Entry("Both set equal", &opv1.ProviderOpenShift, &opv1.ProviderOpenShift, &opv1.ProviderOpenShift),
		Entry("Both set not matching", &opv1.ProviderEKS, &opv1.ProviderGKE, &opv1.ProviderGKE),
	)

	DescribeTable("merge CNISpec", func(main, second, expect *opv1.CNISpec) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.CNI = main
		}
		if second != nil {
			s.CNI = second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			Expect(inst.CNI).To(BeNil())
		} else {
			Expect(*inst.CNI).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &opv1.CNISpec{Type: opv1.PluginCalico}, nil, &opv1.CNISpec{Type: opv1.PluginCalico}),
		Entry("Second only set", nil, &opv1.CNISpec{Type: opv1.PluginGKE}, &opv1.CNISpec{Type: opv1.PluginGKE}),
		Entry("Both set equal",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC}),
		Entry("Both set not matching",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAzureVNET},
			&opv1.CNISpec{Type: opv1.PluginAzureVNET}),
		Entry("Both set differently but mergable",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{IPAM: &opv1.IPAMSpec{Type: opv1.IPAMPluginAmazonVPC}},
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC, IPAM: &opv1.IPAMSpec{Type: opv1.IPAMPluginAmazonVPC}}),
	)

	Context("test CalicoNetwork merge", func() {
		_BGPE := opv1.BGPEnabled
		_BGPD := opv1.BGPDisabled
		DescribeTable("merge BGP", func(main, second, expect *opv1.BGPOption) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{BGP: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{BGP: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.BGP).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_BGPE, nil, &_BGPE),
			Entry("Second only set", nil, &_BGPD, &_BGPD),
			Entry("Both set equal", &_BGPE, &_BGPE, &_BGPE),
			Entry("Both set not matching", &_BGPE, &_BGPD, &_BGPD),
		)

		DescribeTable("merge IPPools", func(main, second, expect []opv1.IPPool) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{IPPools: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{IPPools: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(inst.CalicoNetwork.IPPools).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []opv1.IPPool{{CIDR: "192.168.0.0/16"}}, nil, []opv1.IPPool{{CIDR: "192.168.0.0/16"}}),
			Entry("Second only set", nil, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}),
			Entry("Both set equal", []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}),
			Entry("Both set not matching", []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "172.16.0.0/8"}}, []opv1.IPPool{{CIDR: "172.16.0.0/8"}}),
		)

		DescribeTable("merge MTU", func(main, second, expect *opv1.CalicoNetworkSpec) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = main
			}
			if second != nil {
				s.CalicoNetwork = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)},
				nil,
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)}),
			Entry("Second only set",
				nil,
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)}),
			Entry("Both set equal",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1440)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(1440)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(1440)}),
			Entry("Both set not matching",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1460)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8981)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8981)}),
			Entry("Main only set with cfg override",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)},
				&opv1.CalicoNetworkSpec{},
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)}),
			Entry("Override only set with empty cfg",
				&opv1.CalicoNetworkSpec{},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)}),
		)

		_true := true
		DescribeTable("merge NodeAddressAutodetectionV4", func(main, second, expect *opv1.NodeAddressAutodetection) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV4: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV4: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.NodeAddressAutodetectionV4).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set",
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}, nil,
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}),
			Entry("Second only set", nil,
				&opv1.NodeAddressAutodetection{FirstFound: &_true},
				&opv1.NodeAddressAutodetection{FirstFound: &_true}),
			Entry("Both set equal",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}}),
			Entry("Both set not matching",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.6.0/24", "192.168.11.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.6.0/24", "192.168.11.0/24"}}),
		)

		DescribeTable("merge NodeAddressAutodetectionV6", func(main, second, expect *opv1.NodeAddressAutodetection) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV6: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV6: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.NodeAddressAutodetectionV6).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set",
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}, nil,
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}),
			Entry("Second only set", nil,
				&opv1.NodeAddressAutodetection{FirstFound: &_true},
				&opv1.NodeAddressAutodetection{FirstFound: &_true}),
			Entry("Both set equal",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}}),
			Entry("Both set not matching",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:000f::/96", "fd00:000d::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:000f::/96", "fd00:000d::/96"}}),
		)

		_hpe := opv1.HostPortsEnabled
		_hpd := opv1.HostPortsDisabled
		DescribeTable("merge HostPorts", func(main, second, expect *opv1.HostPortsType) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{HostPorts: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{HostPorts: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.HostPorts).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_hpe, nil, &_hpe),
			Entry("Second only set", nil, &_hpd, &_hpd),
			Entry("Both set equal", &_hpe, &_hpe, &_hpe),
			Entry("Both set not matching", &_hpe, &_hpd, &_hpd),
		)

		_miNone := opv1.MultiInterfaceModeNone
		_miMultus := opv1.MultiInterfaceModeMultus
		DescribeTable("merge MultiInterfaceMode", func(main, second, expect *opv1.MultiInterfaceMode) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{MultiInterfaceMode: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{MultiInterfaceMode: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.MultiInterfaceMode).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_miNone, nil, &_miNone),
			Entry("Second only set", nil, &_miMultus, &_miMultus),
			Entry("Both set equal", &_miNone, &_miNone, &_miNone),
			Entry("Both set not matching", &_miNone, &_miMultus, &_miMultus),
		)

		_cipfE := opv1.ContainerIPForwardingEnabled
		_cipfD := opv1.ContainerIPForwardingDisabled
		DescribeTable("merge ContainerIPForwarding", func(main, second, expect *opv1.ContainerIPForwardingType) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{ContainerIPForwarding: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{ContainerIPForwarding: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.ContainerIPForwarding).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_cipfE, nil, &_cipfE),
			Entry("Second only set", nil, &_cipfD, &_cipfD),
			Entry("Both set equal", &_cipfE, &_cipfE, &_cipfE),
			Entry("Both set not matching", &_cipfE, &_cipfD, &_cipfD),
		)

		DescribeTable("merge ControlPlaneNodeSelector", func(main, second, expect map[string]string) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.ControlPlaneNodeSelector = main
			}
			if second != nil {
				s.ControlPlaneNodeSelector = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.ControlPlaneNodeSelector).To(BeNil())
			} else {
				Expect(inst.ControlPlaneNodeSelector).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", map[string]string{"a": "1"}, nil, map[string]string{"a": "1"}),
			Entry("Second only set", nil, map[string]string{"b": "2"}, map[string]string{"b": "2"}),
			Entry("Both set equal", map[string]string{"a": "1"}, map[string]string{"a": "1"}, map[string]string{"a": "1"}),
			Entry("Both set not matching", map[string]string{"a": "1"}, map[string]string{"b": "2"}, map[string]string{"b": "2"}),
		)
		//TODO: Have some test that have different fields set and they merge.

		DescribeTable("merge multiple CalicoNetwork fields", func(main, second, expect *opv1.CalicoNetworkSpec) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = main
			}
			if second != nil {
				s.CalicoNetwork = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(inst.CalicoNetwork).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged",
				&opv1.CalicoNetworkSpec{
					BGP: &_BGPE,
					MTU: intPtr(100),
				},
				&opv1.CalicoNetworkSpec{
					NodeAddressAutodetectionV4: &opv1.NodeAddressAutodetection{Interface: "enp0s*"},
					HostPorts:                  &_hpe,
				},
				&opv1.CalicoNetworkSpec{
					BGP:                        &_BGPE,
					MTU:                        intPtr(100),
					NodeAddressAutodetectionV4: &opv1.NodeAddressAutodetection{Interface: "enp0s*"},
					HostPorts:                  &_hpe,
				}),
			Entry("Different fields in the two are merged but some are overridden",
				&opv1.CalicoNetworkSpec{
					BGP: &_BGPE,
					MTU: intPtr(100),
				},
				&opv1.CalicoNetworkSpec{
					MTU:       intPtr(200),
					HostPorts: &_hpe,
				},
				&opv1.CalicoNetworkSpec{
					BGP:       &_BGPE,
					MTU:       intPtr(200),
					HostPorts: &_hpe,
				}),
		)
	})

	DescribeTable("merge NodeMetricsPort", func(main, second, expect *int32) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.NodeMetricsPort = main
		}
		if second != nil {
			s.NodeMetricsPort = second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			Expect(inst.NodeMetricsPort).To(BeNil())
		} else {
			Expect(*inst.NodeMetricsPort).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", intPtr(1500), nil, intPtr(1500)),
		Entry("Second only set", nil, intPtr(8980), intPtr(8980)),
		Entry("Both set equal", intPtr(1440), intPtr(1440), intPtr(1440)),
		Entry("Both set not matching", intPtr(1460), intPtr(8981), intPtr(8981)),
	)

	DescribeTable("merge FlexVolumePath", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.FlexVolumePath = main
		}
		if second != "" {
			s.FlexVolumePath = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.FlexVolumePath).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "pathx", nil, "pathx"),
		Entry("Second only set", nil, "pathx", "pathx"),
		Entry("Both set equal", "pathx", "pathx", "pathx"),
		Entry("Both set not matching", "pathx", "pathy", "pathy"),
	)

	_1 := intstr.FromInt(1)
	_roll1 := appsv1.DaemonSetUpdateStrategy{
		Type:          appsv1.RollingUpdateDaemonSetStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDaemonSet{MaxUnavailable: &_1},
	}
	_2 := intstr.FromInt(2)
	_roll2 := appsv1.DaemonSetUpdateStrategy{
		Type:          appsv1.RollingUpdateDaemonSetStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDaemonSet{MaxUnavailable: &_2},
	}
	DescribeTable("merge NodeUpdateStrategy", func(main, second, expect *appsv1.DaemonSetUpdateStrategy) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.NodeUpdateStrategy = *main
		}
		if second != nil {
			s.NodeUpdateStrategy = *second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			var x appsv1.DaemonSetUpdateStrategy
			Expect(inst.NodeUpdateStrategy).To(Equal(x))
		} else {
			Expect(inst.NodeUpdateStrategy).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &_roll1, nil, &_roll1),
		Entry("Second only set", nil, &_roll2, &_roll2),
		Entry("Both set equal", &_roll1, &_roll1, &_roll1),
		Entry("Both set not matching", &_roll1, &_roll2, &_roll2),
	)

	_nodeComp := opv1.ComponentResource{
		ComponentName: opv1.ComponentNameNode,
		ResourceRequirements: &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
		},
	}
	_typhaComp := opv1.ComponentResource{
		ComponentName: opv1.ComponentNameTypha,
		ResourceRequirements: &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceMemory: resource.MustParse("500Mi")},
		},
	}
	DescribeTable("merge ComponentResources", func(main, second, expect []opv1.ComponentResource) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.ComponentResources = main
		}
		if second != nil {
			s.ComponentResources = second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			Expect(inst.ComponentResources).To(HaveLen(0))
		} else {
			Expect(inst.ComponentResources).To(ConsistOf(expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set",
			[]opv1.ComponentResource{_nodeComp},
			nil,
			[]opv1.ComponentResource{_nodeComp}),
		Entry("Second only set",
			nil,
			[]opv1.ComponentResource{_typhaComp},
			[]opv1.ComponentResource{_typhaComp}),
		Entry("Both set equal",
			[]opv1.ComponentResource{_nodeComp},
			[]opv1.ComponentResource{_nodeComp},
			[]opv1.ComponentResource{_nodeComp}),
		Entry("Both set not matching",
			[]opv1.ComponentResource{_nodeComp},
			[]opv1.ComponentResource{_typhaComp},
			[]opv1.ComponentResource{_typhaComp}),
	)

	var metadataTests = []TableEntry{
		// func(main, second, expect *opv1.Metadata)
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set (labels only)", &opv1.Metadata{Labels: map[string]string{"a": "1"}}, nil, &opv1.Metadata{Labels: map[string]string{"a": "1"}}),
		Entry("Main only set (annots only)", &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, nil, &opv1.Metadata{Annotations: map[string]string{"a": "1"}}),
		Entry("Main only set (both)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, nil,
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Second only set (labels only)", nil, &opv1.Metadata{Labels: map[string]string{"a": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}}),
		Entry("Second only set (annots only)", nil, &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, &opv1.Metadata{Annotations: map[string]string{"a": "1"}}),
		Entry("Second only set (both)", nil, &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Both set equal (labels only)", &opv1.Metadata{Labels: map[string]string{"a": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}}),
		Entry("Both set equal (annots only)", &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, &opv1.Metadata{Annotations: map[string]string{"a": "1"}},
			&opv1.Metadata{Annotations: map[string]string{"a": "1"}}),
		Entry("Both set equal (both)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Both set not equal (labels only)", &opv1.Metadata{Labels: map[string]string{"a": "1"}}, &opv1.Metadata{Labels: map[string]string{"b": "2"}},
			&opv1.Metadata{Labels: map[string]string{"b": "2"}}),
		Entry("Both set not equal (annots only)", &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, &opv1.Metadata{Annotations: map[string]string{"b": "2"}},
			&opv1.Metadata{Annotations: map[string]string{"b": "2"}}),
		Entry("Both set not equal (both differ)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"c": "2"}},
			&opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"c": "2"}}),
		Entry("Both set not equal (labels differ)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"b": "1"}},
			&opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Both set not equal (annots differ)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"c": "2"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"c": "2"}}),
	}
	var minReadySecondsTests = []TableEntry{
		// func(main, second, expect *int32)
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", intPtr(23), nil, intPtr(23)),
		Entry("Second only set", nil, intPtr(23), intPtr(23)),
		Entry("Both set equal", intPtr(23), intPtr(23), intPtr(23)),
		Entry("Both set not equal", intPtr(23), intPtr(42), intPtr(42)),
	}

	var nodeSelectorTests = []TableEntry{
		// func(main, second, expect map[string]string)
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", map[string]string{"a1": "1"}, nil, map[string]string{"a1": "1"}),
		Entry("Second only set", nil, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
		Entry("Both set equal", map[string]string{"a1": "1"}, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
		Entry("Both set not equal", map[string]string{"a1": "1"}, map[string]string{"a1": "2", "b1": "3"}, map[string]string{"a1": "2", "b1": "3"}),
		Entry("Both set not equal, override empty", map[string]string{"a1": "1"}, map[string]string{}, map[string]string{}),
	}

	_resources1 := v1.ResourceRequirements{
		Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
		Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
	}
	_resources2 := v1.ResourceRequirements{
		Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
		Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
	}
	_container1a := v1.Container{Name: "1a", Resources: _resources1}
	_container1b := v1.Container{Name: "1b", Resources: _resources2}
	_container2 := v1.Container{Name: "2", Resources: _resources2}
	var containerTests = []TableEntry{
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", []v1.Container{_container1a, _container2}, nil, []v1.Container{_container1a, _container2}),
		Entry("Second only set", nil, []v1.Container{_container1a, _container2}, []v1.Container{_container1a, _container2}),
		Entry("Both set equal", []v1.Container{_container1a, _container2}, []v1.Container{_container1a, _container2}, []v1.Container{_container1a, _container2}),
		Entry("Both set not equal", []v1.Container{_container1a, _container2}, []v1.Container{_container1b, _container2}, []v1.Container{_container1b, _container2}),
	}

	_aff1 := &v1.Affinity{
		NodeAffinity: &v1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
				NodeSelectorTerms: []v1.NodeSelectorTerm{{
					MatchExpressions: []v1.NodeSelectorRequirement{{
						Key:      "custom-affinity-key",
						Operator: v1.NodeSelectorOpExists,
					}},
				}},
			},
		},
	}
	_aff2 := &v1.Affinity{
		NodeAffinity: &v1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
				NodeSelectorTerms: []v1.NodeSelectorTerm{{
					MatchExpressions: []v1.NodeSelectorRequirement{{
						Key:      "custom-affinity-key2",
						Operator: v1.NodeSelectorOpExists,
					}},
				}},
			},
		},
	}
	_affEmpty := &v1.Affinity{}
	var affinityTests = []TableEntry{
		// func(main, second, expect *v1.Affinity)
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", _aff1, nil, _aff1),
		Entry("Second only set", nil, _aff1, _aff1),
		Entry("Both set equal", _aff1, _aff1, _aff1),
		Entry("Both set not equal", _aff1, _aff2, _aff2),
		Entry("Both set not equal, override empty", _aff1, _affEmpty, _affEmpty),
	}

	_toleration1 := v1.Toleration{
		Key:      "foo",
		Operator: v1.TolerationOpEqual,
		Value:    "bar",
	}
	_toleration2 := v1.Toleration{
		Key:      "bar",
		Operator: v1.TolerationOpEqual,
		Value:    "baz",
	}
	var tolerationsTests = []TableEntry{
		// func(main, second, expect []v1.Toleration)
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", []v1.Toleration{_toleration1}, nil, []v1.Toleration{_toleration1}),
		Entry("Second only set", nil, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
		Entry("Both set equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
		Entry("Both set not equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration2}, []v1.Toleration{_toleration2}),
		Entry("Both set not equal, override empty", []v1.Toleration{_toleration1}, []v1.Toleration{}, []v1.Toleration{}),
	}

	Context("test CalicoNodeDaemonSet merge", func() {
		var m opv1.InstallationSpec
		var s opv1.InstallationSpec

		BeforeEach(func() {
			m = opv1.InstallationSpec{
				CalicoNodeDaemonSet: &opv1.CalicoNodeDaemonSet{
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{},
						},
					},
				},
			}
			s = opv1.InstallationSpec{
				CalicoNodeDaemonSet: &opv1.CalicoNodeDaemonSet{
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{},
						},
					},
				},
			}

		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty installation spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNodeDaemonSet = &opv1.CalicoNodeDaemonSet{Metadata: main}
			}
			if second != nil {
				s.CalicoNodeDaemonSet = &opv1.CalicoNodeDaemonSet{Metadata: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge minReadySeconds", func(main, second, expect *int32) {
			m.CalicoNodeDaemonSet.Spec.MinReadySeconds = main
			s.CalicoNodeDaemonSet.Spec.MinReadySeconds = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.MinReadySeconds).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Spec.MinReadySeconds).To(Equal(*expect))
			}
		}, minReadySecondsTests...)

		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.CalicoNodeDaemonSet.Spec.Template.Metadata = main
			s.CalicoNodeDaemonSet.Spec.Template.Metadata = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge initContainers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.CalicoNodeDaemonSetInitContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.CalicoNodeDaemonSetInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.CalicoNodeDaemonSetInitContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.CalicoNodeDaemonSetInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = mainContainers
			s.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = secondContainers

			var expectedContainers []opv1.CalicoNodeDaemonSetInitContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.CalicoNodeDaemonSetInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		DescribeTable("merge containers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.CalicoNodeDaemonSetContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.CalicoNodeDaemonSetContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.CalicoNodeDaemonSetContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.CalicoNodeDaemonSetContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = mainContainers
			s.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = secondContainers

			var expectedContainers []opv1.CalicoNodeDaemonSetContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.CalicoNodeDaemonSetContainer{Name: c.Name, Resources: &c.Resources})
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		}, affinityTests...)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		}, nodeSelectorTests...)

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		}, tolerationsTests...)

		DescribeTable("merge multiple fields", func(main, second, expect *opv1.CalicoNodeDaemonSet) {
			// start with empty spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNodeDaemonSet = main
			}
			if second != nil {
				s.CalicoNodeDaemonSet = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.CalicoNodeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{
								Containers: []opv1.CalicoNodeDaemonSetContainer{
									{
										Name: "calico-node",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.CalicoNodeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{
								InitContainers: []opv1.CalicoNodeDaemonSetInitContainer{
									{
										Name: "install-cni",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
				&opv1.CalicoNodeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{
								Containers: []opv1.CalicoNodeDaemonSetContainer{
									{
										Name: "calico-node",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								InitContainers: []opv1.CalicoNodeDaemonSetInitContainer{
									{
										Name: "install-cni",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
			))
	})

	Context("test CalicoKubeControllersDeployment merge", func() {
		var m opv1.InstallationSpec
		var s opv1.InstallationSpec

		BeforeEach(func() {
			m = opv1.InstallationSpec{
				CalicoKubeControllersDeployment: &opv1.CalicoKubeControllersDeployment{
					Spec: &opv1.CalicoKubeControllersDeploymentSpec{
						Template: &opv1.CalicoKubeControllersDeploymentPodTemplateSpec{
							Spec: &opv1.CalicoKubeControllersDeploymentPodSpec{},
						},
					},
				},
			}
			s = opv1.InstallationSpec{
				CalicoKubeControllersDeployment: &opv1.CalicoKubeControllersDeployment{
					Spec: &opv1.CalicoKubeControllersDeploymentSpec{
						Template: &opv1.CalicoKubeControllersDeploymentPodTemplateSpec{
							Spec: &opv1.CalicoKubeControllersDeploymentPodSpec{},
						},
					},
				},
			}

		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty installation spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoKubeControllersDeployment = &opv1.CalicoKubeControllersDeployment{Metadata: main}
			}
			if second != nil {
				s.CalicoKubeControllersDeployment = &opv1.CalicoKubeControllersDeployment{Metadata: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment).To(BeNil())
			} else {
				Expect(*inst.CalicoKubeControllersDeployment.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge minReadySeconds", func(main, second, expect *int32) {
			m.CalicoKubeControllersDeployment.Spec.MinReadySeconds = main
			s.CalicoKubeControllersDeployment.Spec.MinReadySeconds = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment.Spec.MinReadySeconds).To(BeNil())
			} else {
				Expect(*inst.CalicoKubeControllersDeployment.Spec.MinReadySeconds).To(Equal(*expect))
			}
		}, minReadySecondsTests...)

		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.CalicoKubeControllersDeployment.Spec.Template.Metadata = main
			s.CalicoKubeControllersDeployment.Spec.Template.Metadata = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*inst.CalicoKubeControllersDeployment.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge containers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.CalicoKubeControllersDeploymentContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.CalicoKubeControllersDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.CalicoKubeControllersDeploymentContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.CalicoKubeControllersDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = mainContainers
			s.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = secondContainers

			var expectedContainers []opv1.CalicoKubeControllersDeploymentContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.CalicoKubeControllersDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity = main
			s.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*inst.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		}, affinityTests...)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector = main
			s.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		}, nodeSelectorTests...)

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.CalicoKubeControllersDeployment.Spec.Template.Spec.Tolerations = main
			s.CalicoKubeControllersDeployment.Spec.Template.Spec.Tolerations = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(inst.CalicoKubeControllersDeployment.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		}, tolerationsTests...)

		DescribeTable("merge multiple fields", func(main, second, expect *opv1.CalicoKubeControllersDeployment) {
			// start with empty spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoKubeControllersDeployment = main
			}
			if second != nil {
				s.CalicoKubeControllersDeployment = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoKubeControllersDeployment).To(BeNil())
			} else {
				Expect(*inst.CalicoKubeControllersDeployment).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.CalicoKubeControllersDeployment{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.CalicoKubeControllersDeploymentSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoKubeControllersDeploymentPodTemplateSpec{
							Spec: &opv1.CalicoKubeControllersDeploymentPodSpec{
								Containers: []opv1.CalicoKubeControllersDeploymentContainer{
									{
										Name: "calico-kube-controllers",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.CalicoKubeControllersDeployment{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoKubeControllersDeploymentSpec{
						Template: &opv1.CalicoKubeControllersDeploymentPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoKubeControllersDeploymentPodSpec{
								Containers: []opv1.CalicoKubeControllersDeploymentContainer{
									{
										Name: "calico-kube-controllers",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
				&opv1.CalicoKubeControllersDeployment{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoKubeControllersDeploymentSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoKubeControllersDeploymentPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoKubeControllersDeploymentPodSpec{
								Containers: []opv1.CalicoKubeControllersDeploymentContainer{
									{
										Name: "calico-kube-controllers",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
			))
	})

	Context("test TyphaDeployment merge", func() {
		var m opv1.InstallationSpec
		var s opv1.InstallationSpec

		BeforeEach(func() {
			m = opv1.InstallationSpec{
				TyphaDeployment: &opv1.TyphaDeployment{
					Spec: &opv1.TyphaDeploymentSpec{
						Template: &opv1.TyphaDeploymentPodTemplateSpec{
							Spec: &opv1.TyphaDeploymentPodSpec{},
						},
					},
				},
			}
			s = opv1.InstallationSpec{
				TyphaDeployment: &opv1.TyphaDeployment{
					Spec: &opv1.TyphaDeploymentSpec{
						Template: &opv1.TyphaDeploymentPodTemplateSpec{
							Spec: &opv1.TyphaDeploymentPodSpec{},
						},
					},
				},
			}

		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty installation spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.TyphaDeployment = &opv1.TyphaDeployment{Metadata: main}
			}
			if second != nil {
				s.TyphaDeployment = &opv1.TyphaDeployment{Metadata: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment).To(BeNil())
			} else {
				Expect(*inst.TyphaDeployment.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge minReadySeconds", func(main, second, expect *int32) {
			m.TyphaDeployment.Spec.MinReadySeconds = main
			s.TyphaDeployment.Spec.MinReadySeconds = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment.Spec.MinReadySeconds).To(BeNil())
			} else {
				Expect(*inst.TyphaDeployment.Spec.MinReadySeconds).To(Equal(*expect))
			}
		}, minReadySecondsTests...)

		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.TyphaDeployment.Spec.Template.Metadata = main
			s.TyphaDeployment.Spec.Template.Metadata = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*inst.TyphaDeployment.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge initContainers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.TyphaDeploymentInitContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.TyphaDeploymentInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.TyphaDeploymentInitContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.TyphaDeploymentInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.TyphaDeployment.Spec.Template.Spec.InitContainers = mainContainers
			s.TyphaDeployment.Spec.Template.Spec.InitContainers = secondContainers

			var expectedContainers []opv1.TyphaDeploymentInitContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.TyphaDeploymentInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.InitContainers).To(BeNil())
			} else {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.InitContainers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		// No init containers in CalicoKubeControllersDeployment.

		DescribeTable("merge containers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.TyphaDeploymentContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.TyphaDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.TyphaDeploymentContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.TyphaDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.TyphaDeployment.Spec.Template.Spec.Containers = mainContainers
			s.TyphaDeployment.Spec.Template.Spec.Containers = secondContainers

			var expectedContainers []opv1.TyphaDeploymentContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.TyphaDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.Containers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.TyphaDeployment.Spec.Template.Spec.Affinity = main
			s.TyphaDeployment.Spec.Template.Spec.Affinity = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*inst.TyphaDeployment.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		}, affinityTests...)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.TyphaDeployment.Spec.Template.Spec.NodeSelector = main
			s.TyphaDeployment.Spec.Template.Spec.NodeSelector = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		}, nodeSelectorTests...)

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.TyphaDeployment.Spec.Template.Spec.Tolerations = main
			s.TyphaDeployment.Spec.Template.Spec.Tolerations = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(inst.TyphaDeployment.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		}, tolerationsTests...)

		DescribeTable("merge multiple fields", func(main, second, expect *opv1.TyphaDeployment) {
			// start with empty spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.TyphaDeployment = main
			}
			if second != nil {
				s.TyphaDeployment = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.TyphaDeployment).To(BeNil())
			} else {
				Expect(*inst.TyphaDeployment).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.TyphaDeployment{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.TyphaDeploymentSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.TyphaDeploymentPodTemplateSpec{
							Spec: &opv1.TyphaDeploymentPodSpec{
								Containers: []opv1.TyphaDeploymentContainer{
									{
										Name: "calico-typha",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.TyphaDeployment{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.TyphaDeploymentSpec{
						Template: &opv1.TyphaDeploymentPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.TyphaDeploymentPodSpec{
								InitContainers: []opv1.TyphaDeploymentInitContainer{
									{
										Name: "typha-certs-key-cert-provisioner",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
				&opv1.TyphaDeployment{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.TyphaDeploymentSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.TyphaDeploymentPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.TyphaDeploymentPodSpec{
								Containers: []opv1.TyphaDeploymentContainer{
									{
										Name: "calico-typha",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								InitContainers: []opv1.TyphaDeploymentInitContainer{
									{
										Name: "typha-certs-key-cert-provisioner",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
			))
	})

	Context("test CalicoWindowsUpgradeDaemonSet merge", func() {
		var m opv1.InstallationSpec
		var s opv1.InstallationSpec

		BeforeEach(func() {
			m = opv1.InstallationSpec{
				CalicoWindowsUpgradeDaemonSet: &opv1.CalicoWindowsUpgradeDaemonSet{
					Spec: &opv1.CalicoWindowsUpgradeDaemonSetSpec{
						Template: &opv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoWindowsUpgradeDaemonSetPodSpec{},
						},
					},
				},
			}
			s = opv1.InstallationSpec{
				CalicoWindowsUpgradeDaemonSet: &opv1.CalicoWindowsUpgradeDaemonSet{
					Spec: &opv1.CalicoWindowsUpgradeDaemonSetSpec{
						Template: &opv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoWindowsUpgradeDaemonSetPodSpec{},
						},
					},
				},
			}

		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty installation spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoWindowsUpgradeDaemonSet = &opv1.CalicoWindowsUpgradeDaemonSet{Metadata: main}
			}
			if second != nil {
				s.CalicoWindowsUpgradeDaemonSet = &opv1.CalicoWindowsUpgradeDaemonSet{Metadata: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoWindowsUpgradeDaemonSet.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge minReadySeconds", func(main, second, expect *int32) {
			m.CalicoWindowsUpgradeDaemonSet.Spec.MinReadySeconds = main
			s.CalicoWindowsUpgradeDaemonSet.Spec.MinReadySeconds = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.MinReadySeconds).To(BeNil())
			} else {
				Expect(*inst.CalicoWindowsUpgradeDaemonSet.Spec.MinReadySeconds).To(Equal(*expect))
			}
		}, minReadySecondsTests...)

		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.CalicoWindowsUpgradeDaemonSet.Spec.Template.Metadata = main
			s.CalicoWindowsUpgradeDaemonSet.Spec.Template.Metadata = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		// No init containers in CalicoWindowsUpgradeDaemonSet

		DescribeTable("merge containers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.CalicoWindowsUpgradeDaemonSetContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.CalicoWindowsUpgradeDaemonSetContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.CalicoWindowsUpgradeDaemonSetContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.CalicoWindowsUpgradeDaemonSetContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Containers = mainContainers
			s.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Containers = secondContainers

			var expectedContainers []opv1.CalicoWindowsUpgradeDaemonSetContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.CalicoWindowsUpgradeDaemonSetContainer{Name: c.Name, Resources: &c.Resources})
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Containers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Affinity = main
			s.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Affinity = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		}, affinityTests...)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.NodeSelector = main
			s.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.NodeSelector = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		}, nodeSelectorTests...)

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Tolerations = main
			s.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Tolerations = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(inst.CalicoWindowsUpgradeDaemonSet.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		}, tolerationsTests...)

		DescribeTable("merge multiple fields", func(main, second, expect *opv1.CalicoWindowsUpgradeDaemonSet) {
			// start with empty spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoWindowsUpgradeDaemonSet = main
			}
			if second != nil {
				s.CalicoWindowsUpgradeDaemonSet = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoWindowsUpgradeDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoWindowsUpgradeDaemonSet).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.CalicoWindowsUpgradeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.CalicoWindowsUpgradeDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoWindowsUpgradeDaemonSetPodSpec{
								Containers: []opv1.CalicoWindowsUpgradeDaemonSetContainer{
									{
										Name: "calico-windows-upgrade",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.CalicoWindowsUpgradeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoWindowsUpgradeDaemonSetSpec{
						Template: &opv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoWindowsUpgradeDaemonSetPodSpec{
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
				&opv1.CalicoWindowsUpgradeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoWindowsUpgradeDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoWindowsUpgradeDaemonSetPodSpec{
								Containers: []opv1.CalicoWindowsUpgradeDaemonSetContainer{
									{
										Name: "calico-windows-upgrade",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
			))
	})

	Context("test APIServerDeployment merge", func() {
		var m opv1.APIServerSpec
		var s opv1.APIServerSpec

		BeforeEach(func() {
			m = opv1.APIServerSpec{
				APIServerDeployment: &opv1.APIServerDeployment{
					Spec: &opv1.APIServerDeploymentSpec{
						Template: &opv1.APIServerDeploymentPodTemplateSpec{
							Spec: &opv1.APIServerDeploymentPodSpec{},
						},
					},
				},
			}
			s = opv1.APIServerSpec{
				APIServerDeployment: &opv1.APIServerDeployment{
					Spec: &opv1.APIServerDeploymentSpec{
						Template: &opv1.APIServerDeploymentPodTemplateSpec{
							Spec: &opv1.APIServerDeploymentPodSpec{},
						},
					},
				},
			}

		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty APIServer  spec
			m = opv1.APIServerSpec{}
			s = opv1.APIServerSpec{}
			if main != nil {
				m.APIServerDeployment = &opv1.APIServerDeployment{Metadata: main}
			}
			if second != nil {
				s.APIServerDeployment = &opv1.APIServerDeployment{Metadata: second}
			}
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment).To(BeNil())
			} else {
				Expect(*res.APIServerDeployment.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge minReadySeconds", func(main, second, expect *int32) {
			m.APIServerDeployment.Spec.MinReadySeconds = main
			s.APIServerDeployment.Spec.MinReadySeconds = second
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment.Spec.MinReadySeconds).To(BeNil())
			} else {
				Expect(*res.APIServerDeployment.Spec.MinReadySeconds).To(Equal(*expect))
			}
		}, minReadySecondsTests...)

		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.APIServerDeployment.Spec.Template.Metadata = main
			s.APIServerDeployment.Spec.Template.Metadata = second
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*res.APIServerDeployment.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests...)

		DescribeTable("merge initContainers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.APIServerDeploymentInitContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.APIServerDeploymentInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.APIServerDeploymentInitContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.APIServerDeploymentInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.APIServerDeployment.Spec.Template.Spec.InitContainers = mainContainers
			s.APIServerDeployment.Spec.Template.Spec.InitContainers = secondContainers

			var expectedContainers []opv1.APIServerDeploymentInitContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.APIServerDeploymentInitContainer{Name: c.Name, Resources: &c.Resources})
			}
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment.Spec.Template.Spec.InitContainers).To(BeNil())
			} else {
				Expect(res.APIServerDeployment.Spec.Template.Spec.InitContainers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		DescribeTable("merge containers", func(main, second, expect []v1.Container) {
			var mainContainers []opv1.APIServerDeploymentContainer
			for _, c := range main {
				mainContainers = append(mainContainers, opv1.APIServerDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			var secondContainers []opv1.APIServerDeploymentContainer
			for _, c := range second {
				secondContainers = append(secondContainers, opv1.APIServerDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			m.APIServerDeployment.Spec.Template.Spec.Containers = mainContainers
			s.APIServerDeployment.Spec.Template.Spec.Containers = secondContainers

			var expectedContainers []opv1.APIServerDeploymentContainer
			for _, c := range expect {
				expectedContainers = append(expectedContainers, opv1.APIServerDeploymentContainer{Name: c.Name, Resources: &c.Resources})
			}
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(res.APIServerDeployment.Spec.Template.Spec.Containers).To(Equal(expectedContainers))
			}
		}, containerTests...)

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.APIServerDeployment.Spec.Template.Spec.Affinity = main
			s.APIServerDeployment.Spec.Template.Spec.Affinity = second
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*res.APIServerDeployment.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		}, affinityTests...)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.APIServerDeployment.Spec.Template.Spec.NodeSelector = main
			s.APIServerDeployment.Spec.Template.Spec.NodeSelector = second
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(res.APIServerDeployment.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		}, nodeSelectorTests...)

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.APIServerDeployment.Spec.Template.Spec.Tolerations = main
			s.APIServerDeployment.Spec.Template.Spec.Tolerations = second
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(res.APIServerDeployment.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		}, tolerationsTests...)

		DescribeTable("merge multiple fields", func(main, second, expect *opv1.APIServerDeployment) {
			// start with empty spec
			m = opv1.APIServerSpec{}
			s = opv1.APIServerSpec{}
			if main != nil {
				m.APIServerDeployment = main
			}
			if second != nil {
				s.APIServerDeployment = second
			}
			res := OverrideAPIServerSpec(m, s)
			if expect == nil {
				Expect(res.APIServerDeployment).To(BeNil())
			} else {
				Expect(*res.APIServerDeployment).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.APIServerDeployment{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.APIServerDeploymentSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.APIServerDeploymentPodTemplateSpec{
							Spec: &opv1.APIServerDeploymentPodSpec{
								InitContainers: []opv1.APIServerDeploymentInitContainer{
									{
										Name: "calico-apiserver-certs-key-cert-provisioner",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("111m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("111m")},
										},
									},
								},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.APIServerDeployment{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.APIServerDeploymentSpec{
						Template: &opv1.APIServerDeploymentPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.APIServerDeploymentPodSpec{
								Containers: []opv1.APIServerDeploymentContainer{
									{
										Name: "calico-apiserver",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								InitContainers: []opv1.APIServerDeploymentInitContainer{
									{
										Name: "calico-apiserver-certs-key-cert-provisioner",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
				&opv1.APIServerDeployment{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.APIServerDeploymentSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.APIServerDeploymentPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.APIServerDeploymentPodSpec{
								Containers: []opv1.APIServerDeploymentContainer{
									{
										Name: "calico-apiserver",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
										},
									},
								},
								InitContainers: []opv1.APIServerDeploymentInitContainer{
									{
										Name: "calico-apiserver-certs-key-cert-provisioner",
										Resources: &v1.ResourceRequirements{
											Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
											Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
										},
									},
								},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
			))
	})

	Context("all fields handled", func() {
		var defaulted opv1.InstallationSpec
		BeforeEach(func() {
			defaulter := test.NewNonZeroStructDefaulter()
			Expect(defaulter.SetDefault(&defaulted)).ToNot(HaveOccurred())
		})

		It("when set in cfg", func() {
			inst := OverrideInstallationSpec(
				defaulted,
				opv1.InstallationSpec{},
			)

			changeLog, err := diff.Diff(defaulted, inst)
			Expect(err).NotTo(HaveOccurred())

			Expect(changeLog).To(HaveLen(0))
			Expect(reflect.DeepEqual(inst, defaulted)).To(BeTrue(),
				fmt.Sprintf("Differences: %+v", changeLog))
		})
		It("when set in override", func() {
			inst := OverrideInstallationSpec(
				opv1.InstallationSpec{CalicoNetwork: &opv1.CalicoNetworkSpec{}},
				defaulted,
			)

			changeLog, err := diff.Diff(defaulted, inst)
			Expect(err).NotTo(HaveOccurred())
			Expect(changeLog).To(HaveLen(0))
			Expect(reflect.DeepEqual(inst, defaulted)).To(BeTrue(),
				fmt.Sprintf("Differences: %+v", changeLog))
		})
		DescribeTable("merge defaulted", func(cfg, override, expect *opv1.InstallationSpec) {
			inst := OverrideInstallationSpec(*cfg, *override)

			changeLog, err := diff.Diff(inst, *expect)
			Expect(err).NotTo(HaveOccurred())
			Expect(changeLog).To(HaveLen(0))
			Expect(reflect.DeepEqual(inst, defaulted)).To(BeTrue(),
				fmt.Sprintf("Differences: %+v", changeLog))
		},
			// We must pass defaulted as a pointer here because the BeforeEach is processed
			// after the Entrys are evaluated to It.
			Entry("empty cfg",
				&opv1.InstallationSpec{},
				&defaulted,
				&defaulted),
			Entry("empty override",
				&defaulted,
				&opv1.InstallationSpec{},
				&defaulted),
			Entry("empty cfg with substruct defaults",
				&opv1.InstallationSpec{
					CalicoNetwork: &opv1.CalicoNetworkSpec{},
					CNI:           &opv1.CNISpec{},
				},
				&defaulted,
				&defaulted),
			Entry("empty override with substruct defaults",
				&defaulted,
				&opv1.InstallationSpec{
					CalicoNetwork: &opv1.CalicoNetworkSpec{},
					CNI:           &opv1.CNISpec{},
				},
				&defaulted),
		)
	})
})
