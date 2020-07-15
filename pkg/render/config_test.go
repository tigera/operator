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

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Render Config tests", func() {
	var install *operator.Installation
	var expectedCfg render.NetworkConfig
	BeforeEach(func() {
		hpe := operator.HostPortsEnabled
		install = &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						operator.IPPool{
							CIDR:          "10.0.0.0/24",
							Encapsulation: "IPIP",
							NATOutgoing:   "Enabled",
						},
					},
					HostPorts: &hpe,
				},
			},
		}
		expectedCfg = render.NetworkConfig{
			CNIPlugin:            operator.PluginCalico,
			NodenameFileOptional: false,
			IPPools: []operator.IPPool{
				operator.IPPool{
					CIDR:          "10.0.0.0/24",
					Encapsulation: "IPIP",
					NATOutgoing:   "Enabled",
				},
			},
			MTU:       0,
			HostPorts: true,
		}
	})
	It("standard conversion", func() {
		nc := render.GenerateRenderConfig(install)
		Expect(nc).To(Equal(expectedCfg))
	})
	It("no CalicoNetwork conversion", func() {
		install.Spec.CalicoNetwork = nil
		nc := render.GenerateRenderConfig(install)
		Expect(nc).To(Equal(render.NetworkConfig{
			CNIPlugin:            operator.PluginCalico,
			NodenameFileOptional: false,
		}))
	})
	It("mtu specified", func() {
		mtu := int32(1234)
		install.Spec.CalicoNetwork.MTU = &mtu
		nc := render.GenerateRenderConfig(install)
		expectedCfg.MTU = 1234
		Expect(nc).To(Equal(expectedCfg))
	})
	It("plugin specified", func() {
		install.Spec.CNI.Type = operator.PluginGKE
		install.Spec.CalicoNetwork = nil
		nc := render.GenerateRenderConfig(install)
		Expect(nc.CNIPlugin).To(Equal(operator.PluginGKE))
		Expect(nc).To(Equal(render.NetworkConfig{
			CNIPlugin:            operator.PluginGKE,
			NodenameFileOptional: false,
			MTU:                  0,
			HostPorts:            false,
		}))
	})
	It("convert DockerEE to NodeNameFileOptional", func() {
		install.Spec.KubernetesProvider = operator.ProviderDockerEE
		nc := render.GenerateRenderConfig(install)
		// Only difference from standard conversion is NodenameFileOptional
		expectedCfg.NodenameFileOptional = true
		Expect(nc).To(Equal(expectedCfg))
	})
	It("IP pool specified", func() {
		install.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			operator.IPPool{
				CIDR:          "192.168.0.0/16",
				Encapsulation: "VXLAN",
				NATOutgoing:   "Disabled",
			},
		}
		nc := render.GenerateRenderConfig(install)
		expectedCfg.IPPools = []operator.IPPool{
			operator.IPPool{
				CIDR:          "192.168.0.0/16",
				Encapsulation: "VXLAN",
				NATOutgoing:   "Disabled",
			},
		}
		Expect(nc).To(Equal(expectedCfg))
	})
})
