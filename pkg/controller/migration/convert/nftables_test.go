// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	pcv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"

	v1 "k8s.io/api/core/v1"
	kscheme "k8s.io/client-go/kubernetes/scheme"
)

var _ = Describe("convert nftables mode", func() {
	var (
		comps  = emptyComponents()
		i      = &operatorv1.Installation{}
		f      = &crdv1.FelixConfiguration{}
		scheme = kscheme.Scheme
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &operatorv1.Installation{}
		f = emptyFelixConfig()
		Expect(apis.AddToScheme(scheme)).ToNot(HaveOccurred())
	})

	It("converts nftables mode from FelixConfiguration Enabled", func() {
		nftMode := pcv1.NFTablesModeEnabled
		f.Spec.NFTablesMode = &nftMode
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()

		err := handleNftables(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(*i.Spec.CalicoNetwork.LinuxDataplane).To(BeEquivalentTo(operatorv1.LinuxDataplaneNftables))
		Expect(i.Spec.CalicoNetwork.HostPorts).To(BeNil())
	})

	It("converts nftables mode from FelixConfiguration Disabled", func() {
		nftMode := pcv1.NFTablesModeDisabled
		f.Spec.NFTablesMode = &nftMode
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()
		err := handleNftables(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
	})

	It("rejects migration if another dataplane is already set", func() {
		nftMode := pcv1.NFTablesModeEnabled
		f.Spec.NFTablesMode = &nftMode
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()

		// Set the Installation to already have a dataplane mode set.
		bpf := operatorv1.LinuxDataplaneBPF
		i.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{LinuxDataplane: &bpf}

		err := handleNftables(&comps, i)
		Expect(err).To(HaveOccurred())
	})

	It("check with no felixconfig", func() {
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM).Build()
		err := handleNftables(&comps, i)
		Expect(err).To(HaveOccurred())
	})

	It("converts nftables mode from environment variable (enabled)", func() {
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
			Name:  "FELIX_NFTABLESMODE",
			Value: "Enabled",
		}}
		err := handleNftables(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(*i.Spec.CalicoNetwork.LinuxDataplane).To(BeEquivalentTo(operatorv1.LinuxDataplaneNftables))
	})

	It("converts nftables mode from environment variable (disabled)", func() {
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
			Name:  "FELIX_NFTABLESMODE",
			Value: "Disabled",
		}}
		err := handleNftables(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
	})
})
