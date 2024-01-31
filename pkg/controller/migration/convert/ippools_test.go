// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/test"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
)

var _ = Describe("Convert network tests", func() {
	var ctx = context.Background()
	var pool *crdv1.IPPool
	var scheme *runtime.Scheme
	var trueValue bool
	var falseValue bool

	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		pool = crdv1.NewIPPool()
		pool.Spec = crdv1.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    crdv1.IPIPModeAlways,
			NATOutgoing: true,
		}
		trueValue = true
		falseValue = false
	})
	Describe("handle IPPool migration", func() {
		var v4pool1 *crdv1.IPPool
		var v4pool2 *crdv1.IPPool
		var v4pooldefault *crdv1.IPPool
		var v6pool1 *crdv1.IPPool
		var v6pool2 *crdv1.IPPool
		var v6pooldefault *crdv1.IPPool
		BeforeEach(func() {
			v4pool1 = crdv1.NewIPPool()
			v4pool1.Name = "not-default"
			v4pool1.Spec = crdv1.IPPoolSpec{
				CIDR:        "1.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
			v4pool2 = crdv1.NewIPPool()
			v4pool2.Name = "not-default2"
			v4pool2.Spec = crdv1.IPPoolSpec{
				CIDR:        "2.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
			v4pooldefault = crdv1.NewIPPool()
			v4pooldefault.Name = "default-ipv4-pool"
			v4pooldefault.Spec = crdv1.IPPoolSpec{
				CIDR:        "3.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
			v6pool1 = crdv1.NewIPPool()
			v6pool1.Name = "not-default1-v6"
			v6pool1.Spec = crdv1.IPPoolSpec{
				CIDR:        "ff00:0001::/24",
				IPIPMode:    crdv1.IPIPModeNever,
				NATOutgoing: true,
			}
			v6pool2 = crdv1.NewIPPool()
			v6pool2.Name = "not-default2"
			v6pool2.Spec = crdv1.IPPoolSpec{
				CIDR:        "ff00:0002::/24",
				IPIPMode:    crdv1.IPIPModeNever,
				NATOutgoing: true,
			}
			v6pooldefault = crdv1.NewIPPool()
			v6pooldefault.Name = "default-ipv6-pool"
			v6pooldefault.Spec = crdv1.IPPoolSpec{
				CIDR:        "ff00:0003::/24",
				IPIPMode:    crdv1.IPIPModeNever,
				NATOutgoing: true,
			}
		})
		It("should convert default IPv4 pool", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			c := test.DefaultFakeClientBuilder(scheme).WithObjects(ds, v4pool1, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(Equal([]operatorv1.IPPool{{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationIPIP,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				DisableBGPExport: &falseValue,
			}}))
		})
		It("should handle no pools", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers = nil
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
				{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
				{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			}

			c := test.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyFelixConfig()).Build()
			_, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
		})
		DescribeTable("should pick v4 default pool", func(envcidr, expectcidr string) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_IPV4POOL_CIDR",
				Value: envcidr,
			}}
			c := test.DefaultFakeClientBuilder(scheme).WithObjects(ds, v4pool1, v4pool2, v4pooldefault, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operatorv1.EncapsulationIPIP))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].NATOutgoing).To(Equal(operatorv1.NATOutgoingEnabled))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal(expectcidr))
		},
			Entry("find default pool even when CIDR suggests other", "1.168.4.0/24", "3.168.4.0/24"),
			Entry("find default pool", "3.168.4.0/24", "3.168.4.0/24"),
		)
		DescribeTable("should pick v6 default pool", func(envcidr, expectcidr string) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name: "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network",
				         "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"true"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_IPV6POOL_CIDR",
				Value: envcidr,
			}}
			c := test.DefaultFakeClientBuilder(scheme).WithObjects(ds, v6pool1, v6pool2, v6pooldefault, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operatorv1.EncapsulationNone))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].NATOutgoing).To(Equal(operatorv1.NATOutgoingEnabled))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal(expectcidr))
		},
			Entry("find default pool even when CIDR suggests other", "ff00:0001::/24", "ff00:0003::/24"),
			Entry("find default pool", "ff00:0003::/24", "ff00:0003::/24"),
		)
		It("should error on bad pool CIDR", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			v4pool1.Spec.CIDR = "1.168.0/24"
			c := test.DefaultFakeClientBuilder(scheme).WithObjects(ds, v4pool1).Build()
			_, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
		})
		It("should ignore disabled pools", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			// Set env var that would cause us to pick pool
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_IPV4POOL_CIDR",
				Value: "3.168.4.0/24",
			}}
			v4pooldefault.Spec.Disabled = true
			c := test.DefaultFakeClientBuilder(scheme).WithObjects(ds, v4pooldefault, v4pool2, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("2.168.4.0/24"))
		})
		It("should pick v4 and v6 pool", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv6":"true"}}`,
			}}
			c := test.DefaultFakeClientBuilder(scheme).WithObjects(ds, v4pool1, v6pool1, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(ConsistOf([]operatorv1.IPPool{{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationIPIP,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				DisableBGPExport: &falseValue,
			}, {
				CIDR:             "ff00:0001::/24",
				Encapsulation:    operatorv1.EncapsulationNone,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				DisableBGPExport: &falseValue,
			}}))
		})
		DescribeTable("should block mismatch of pools and assign_ip*", func(assigns string, cidrs ...string) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: fmt.Sprintf(`{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", %s}}`, assigns),
			}}
			pools := []runtime.Object{}
			for i, c := range cidrs {
				p := crdv1.NewIPPool()
				p.Name = fmt.Sprintf("not-default-%d", i)
				p.Spec = crdv1.IPPoolSpec{
					CIDR:        c,
					IPIPMode:    crdv1.IPIPModeAlways,
					NATOutgoing: true,
				}
				pools = append(pools, p)
			}
			c := test.DefaultFakeClientBuilder(scheme).WithRuntimeObjects(append([]runtime.Object{ds}, pools...)...).Build()
			_, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
		},
			Entry("v4 pool but no assigning v4", `"assign_ipv4": "false"`, "1.168.4.0/24"),
			Entry("no v4 pool but assigning v4", `"assign_ipv4": "true"`),
			Entry("no v6 pool and assign v6 ", `"assign_ipv4": "false", "assign_ipv6": "true"`, "1.168.4.0/24"),
			Entry("v4 pool but assign v6 and v4", `"assign_ipv4": "true", "assign_ipv6": "true"`, "1.168.4.0/24"),
			Entry("v6 pool but assign v6 and v4", `"assign_ipv4": "true", "assign_ipv6": "true"`, "ff00:0001::/24"),
			Entry("v4 and v6 pool but no assigning v4", `"assign_ipv4": "false", "assign_ipv6": "true"`, "1.168.4.0/24", "ff00:0001::/24"),
			Entry("v4 and v6 pool but no assigning v6", `"assign_ipv4": "true", "assign_ipv6": "false"`, "1.168.4.0/24", "ff00:0001::/24"),
		)

		DescribeTable("test convert pool flags", func(success bool, crdPool crdv1.IPPool, opPool operatorv1.IPPool) {
			p, err := convertPool(crdPool)
			if success {
				Expect(err).NotTo(HaveOccurred())
				Expect(p).To(Equal(opPool))
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			Entry("ipv4, no encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationNone,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				BlockSize:        int32Ptr(27),
				NodeSelector:     "nodeselectorstring",
				DisableBGPExport: &falseValue,
			}),
			Entry("ipv4, vxlan encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeAlways,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationVXLAN,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				BlockSize:        int32Ptr(27),
				NodeSelector:     "nodeselectorstring",
				DisableBGPExport: &falseValue,
			}),
			Entry("ipv4, ipip encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeAlways,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationIPIP,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				BlockSize:        int32Ptr(27),
				NodeSelector:     "nodeselectorstring",
				DisableBGPExport: &falseValue,
			}),
			Entry("ipv4, vxlancross encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeCrossSubnet,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationVXLANCrossSubnet,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				BlockSize:        int32Ptr(27),
				NodeSelector:     "nodeselectorstring",
				DisableBGPExport: &falseValue,
			}),
			Entry("ipv4, ipipcross encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeCrossSubnet,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationIPIPCrossSubnet,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				BlockSize:        int32Ptr(27),
				NodeSelector:     "nodeselectorstring",
				DisableBGPExport: &falseValue,
			}),
			Entry("ipv4, no encap, no nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  false,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationNone,
				NATOutgoing:      operatorv1.NATOutgoingDisabled,
				BlockSize:        int32Ptr(27),
				NodeSelector:     "nodeselectorstring",
				DisableBGPExport: &falseValue,
			}),
			Entry("ipv4, no encap, nat, block 24", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    24,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationNone,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				BlockSize:        int32Ptr(24),
				NodeSelector:     "nodeselectorstring",
				DisableBGPExport: &falseValue,
			}),
			Entry("ipv4, no encap, nat, block 27, different nodeselector", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "othernodeselector",
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationNone,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				BlockSize:        int32Ptr(27),
				NodeSelector:     "othernodeselector",
				DisableBGPExport: &falseValue,
			}),

			Entry("ipv4, invalid encap, nat, block 27", false, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeAlways,
				IPIPMode:     crdv1.IPIPModeAlways,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{}),
			Entry("ipv4, invalid encap2, nat, block 27", false, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeCrossSubnet,
				IPIPMode:     crdv1.IPIPModeAlways,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{}),
			Entry("ipv4, vxlan encap, nat, disableBGPExport true", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:             "1.168.4.0/24",
				VXLANMode:        crdv1.VXLANModeAlways,
				IPIPMode:         crdv1.IPIPModeNever,
				NATOutgoing:      true,
				Disabled:         false,
				DisableBGPExport: true,
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationVXLAN,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				NodeSelector:     "",
				DisableBGPExport: &trueValue,
			}),
			Entry("ipv4, vxlan encap, nat, disableBGPExport false", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:             "1.168.4.0/24",
				VXLANMode:        crdv1.VXLANModeAlways,
				IPIPMode:         crdv1.IPIPModeNever,
				NATOutgoing:      true,
				Disabled:         false,
				DisableBGPExport: false,
			}}, operatorv1.IPPool{
				CIDR:             "1.168.4.0/24",
				Encapsulation:    operatorv1.EncapsulationVXLAN,
				NATOutgoing:      operatorv1.NATOutgoingEnabled,
				NodeSelector:     "",
				DisableBGPExport: &falseValue,
			}),
		)
	})

})
