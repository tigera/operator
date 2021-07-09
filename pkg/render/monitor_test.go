// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("monitor rendering tests", func() {

	const (
		calicoNodePrometheusServiceName = "calico-node-prometheus"
	)

	It("Should render Prometheus resources", func() {
		component := render.Monitor(
			&operatorv1.InstallationSpec{},
			[]*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
			},
		)

		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()

		Expect(toDelete).To(BeNil())

		// should render correct resources
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{common.TigeraPrometheusNamespace, "", "", "v1", "Namespace"},
			{"tigera-pull-secret", common.TigeraPrometheusNamespace, "", "", ""},
			{render.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind},
			{render.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind},
			{render.TigeraPrometheusDPRate, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind},
			{render.CalicoNodeMonitor, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{render.ElasticsearchMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{render.FluentdMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PodMonitorsKind},
			{"prometheus-operated-http", common.TigeraPrometheusNamespace, "", "v1", "Service"},
		}

		Expect(len(toCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := toCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)

			if alertmanagerObj, ok := obj.(*monitoringv1.Alertmanager); ok {
				com := components.ComponentPrometheusAlertmanager
				expectedImage := fmt.Sprintf("%s%s:%s", components.PrometheusRegistry, com.Image, com.Version)
				Expect(*alertmanagerObj.Spec.Image).To(Equal(expectedImage))
			} else if prometheusObj, ok := obj.(*monitoringv1.Prometheus); ok {
				com := components.ComponentPrometheus
				expectedImage := fmt.Sprintf("%s%s:%s", components.PrometheusRegistry, com.Image, com.Version)
				Expect(*prometheusObj.Spec.Image).To(Equal(expectedImage))
			} else if obj.GetName() == "prometheus-operated-http" {
				prometheusOperatedHttpServiceManifest := obj.(*corev1.Service)
				Expect(prometheusOperatedHttpServiceManifest.Spec.Selector["prometheus"]).To(Equal(calicoNodePrometheusServiceName))

				Expect(prometheusOperatedHttpServiceManifest.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
				Expect(len(prometheusOperatedHttpServiceManifest.Spec.Ports)).To(Equal(1))
				Expect(prometheusOperatedHttpServiceManifest.Spec.Ports[0].Port).To(Equal(int32(render.PrometheusDefaultPort)))
				Expect(prometheusOperatedHttpServiceManifest.Spec.Ports[0].TargetPort.IntVal).To(Equal(int32(render.PrometheusDefaultPort)))

			}
		}
	})
})
