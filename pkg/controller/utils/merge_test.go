// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
