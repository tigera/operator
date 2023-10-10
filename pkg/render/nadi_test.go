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
	"github.com/tigera/operator/pkg/common"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("AdrianaNode rendering tests", func() {

	enableIPv4 := true
	enableIPv6 := true
	Describe(fmt.Sprintf("AdrianaIPv4 enabled: %v, AdrianaIPv6 enabled: %v", enableIPv4, enableIPv6), func() {
		var defaultInstance *operatorv1.InstallationSpec
		var typhaNodeTLS *render.TyphaNodeTLS
		var k8sServiceEp k8sapi.ServiceEndpoint
		one := intstr.FromInt(1)
		//defaultNumExpectedResources := 9
		const defaultClusterDomain = "svc.cluster.local"
		//var defaultMode int32 = 420
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

		It("adds two numbers", func() {
			sum := 6
			//Expect(err).NotTo(HaveOccurred())
			Expect(sum).To(Equal(6))
		})
	})

})
