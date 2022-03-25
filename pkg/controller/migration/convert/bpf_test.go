// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("convert bpf config", func() {
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
	})

	It("converts bpfenabled felixconfig set to true", func() {
		Expect(apis.AddToScheme(scheme)).ToNot(HaveOccurred())
		bpfEnabled := true
		f.Spec.BPFEnabled = &bpfEnabled
		comps.client = fake.NewFakeClientWithScheme(scheme, f)
		err := handleBPF(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(*i.Spec.CalicoNetwork.LinuxDataplane).To(BeEquivalentTo(operatorv1.LinuxDataplaneBPF))
		Expect(i.Spec.CalicoNetwork.HostPorts).To(BeNil())
	})

	It("converts bpfenabled felixconfig set to false", func() {
		Expect(apis.AddToScheme(scheme)).ToNot(HaveOccurred())
		bpfEnabled := false
		f.Spec.BPFEnabled = &bpfEnabled
		comps.client = fake.NewFakeClientWithScheme(scheme, f)
		err := handleBPF(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
	})

	It("check with no felixconfig", func() {
		Expect(apis.AddToScheme(scheme)).ToNot(HaveOccurred())
		comps.client = fake.NewFakeClientWithScheme(scheme)
		err := handleBPF(&comps, i)
		Expect(err).To(HaveOccurred())
	})
})
