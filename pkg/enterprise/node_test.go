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

package enterprise_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/operator"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("node enterprise image override", func() {
	BeforeEach(func() { enterprise.Register() })
	AfterEach(func() {
		operator.ResetForTest()
		operator.ResetExtensionsForTest()
	})

	It("selects the enterprise node image for the enterprise variant", func() {
		ent := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		Expect(operator.ResolveImage("node", components.ComponentCalicoNode, ent)).To(Equal(components.ComponentTigeraNode))
	})

	It("leaves the default in place for the Calico variant", func() {
		oss := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		Expect(operator.ResolveImage("node", components.ComponentCalicoNode, oss)).To(Equal(components.ComponentCalicoNode))
	})
})

var _ = Describe("node metrics service modifier", func() {
	BeforeEach(func() { enterprise.Register() })
	AfterEach(func() {
		operator.ResetForTest()
		operator.ResetExtensionsForTest()
	})

	It("appends the node metrics service for the enterprise variant", func() {
		ctx := operator.Context{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}}
		out := operator.ApplyPatches(render.ComponentNameNode, ctx, []client.Object{})
		svc, ok := operator.FindObject[*corev1.Service](out, render.CalicoNodeMetricsService)
		Expect(ok).To(BeTrue())
		// default ports when FelixConfiguration is nil: 9081 + 9900, felix-metrics-port absent
		Expect(svc.Spec.Ports).To(HaveLen(2))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(9081)))
		Expect(svc.Spec.Ports[1].Port).To(Equal(int32(9900)))
	})

	It("derives ports and felix-metrics-port from FelixConfiguration", func() {
		reporter := 7081
		metrics := 7091
		enabled := true
		ctx := operator.Context{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			FelixConfiguration: &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{
				PrometheusReporterPort:   &reporter,
				PrometheusMetricsPort:    &metrics,
				PrometheusMetricsEnabled: &enabled,
			}},
		}
		out := operator.ApplyPatches(render.ComponentNameNode, ctx, []client.Object{})
		svc, ok := operator.FindObject[*corev1.Service](out, render.CalicoNodeMetricsService)
		Expect(ok).To(BeTrue())
		Expect(svc.Spec.Ports).To(HaveLen(3))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(7081)))
		Expect(svc.Spec.Ports[2].Name).To(Equal("felix-metrics-port"))
		Expect(svc.Spec.Ports[2].Port).To(Equal(int32(7091)))
	})

	It("does not append it for the Calico variant", func() {
		ctx := operator.Context{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}}
		out := operator.ApplyPatches(render.ComponentNameNode, ctx, []client.Object{})
		_, ok := operator.FindObject[*corev1.Service](out, render.CalicoNodeMetricsService)
		Expect(ok).To(BeFalse())
	})
})
