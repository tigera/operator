// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/sharedconfig"
)

var _ = Describe("FelixConfiguration declarations", func() {
	var r ReconcileInstallation

	nftables := operatorv1.LinuxDataplaneNftables

	BeforeEach(func() {
		r = ReconcileInstallation{ext: testExtensions.Installation()}
	})

	install := func() *operatorv1.Installation {
		return &operatorv1.Installation{Spec: operatorv1.InstallationSpec{
			CNI:           &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{LinuxDataplane: &nftables},
		}}
	}

	declaredPaths := func(i *operatorv1.Installation, current *v3.FelixConfiguration) []string {
		d, err := r.declareFelixConfiguration(i)(current)
		Expect(err).NotTo(HaveOccurred())
		paths := []string{}
		for path := range d.Policies {
			paths = append(paths, path)
		}
		return paths
	}

	It("declares the same fields no matter what the current object holds", func() {
		empty := declaredPaths(install(), &v3.FelixConfiguration{})
		Expect(empty).To(ConsistOf(
			"spec.healthPort",
			"spec.vxlanVNI",
			"spec.vxlanPort",
			"spec.nftablesMode",
		))

		// Every field the operator defaults is already set, by the operator or by anyone else.
		populated := declaredPaths(install(), &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{
			HealthPort:   ptr.To(1234),
			VXLANVNI:     ptr.To(9999),
			VXLANPort:    ptr.To(1111),
			NFTablesMode: ptr.To(v3.NFTablesModeDisabled),
		}})
		Expect(populated).To(ConsistOf(empty))
	})

	It("declares the values it wants, not the values already there", func() {
		current := &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(1234)}}
		d, err := r.declareFelixConfiguration(install())(current)
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Owned.Spec.HealthPort).To(Equal(ptr.To(9099)))
		Expect(d.Policies["spec.healthPort"]).To(Equal(sharedconfig.ConflictDefer))
	})

	It("defers to a user on defaults and overrides them on modes it owns outright", func() {
		i := install()
		i.Spec.CalicoNetwork.ClusterRoutingMode = ptr.To(operatorv1.ClusterRoutingModeFelix)
		d, err := r.declareFelixConfiguration(i)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Manager).To(Equal(felixConfigFieldManager))
		Expect(d.Policies["spec.programClusterRoutes"]).To(Equal(sharedconfig.ConflictOverride))
		Expect(d.Owned.Spec.ProgramClusterRoutes).To(Equal(ptr.To("Enabled")))
	})

	It("declares bpfEnabled under its own manager, refusing to fight over it", func() {
		d, err := r.declareBPFEnabled(context.Background(), install(), false)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Manager).To(Equal(bpfFieldManager))
		Expect(d.Policies).To(HaveLen(1))
		Expect(d.Policies["spec.bpfEnabled"]).To(Equal(sharedconfig.ConflictError))
		Expect(d.Owned.Spec.BPFEnabled).To(Equal(ptr.To(false)))
	})
})
