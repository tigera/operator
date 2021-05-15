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

package utils

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
)

func AddAlertmanagerWatch(c controller.Controller) error {
	return addNamespacedWatch(c, &monitoringv1.Alertmanager{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.AlertmanagersKind, APIVersion: render.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: render.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace},
	})
}

func AddPrometheusWatch(c controller.Controller) error {
	return addNamespacedWatch(c, &monitoringv1.Prometheus{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.PrometheusesKind, APIVersion: render.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: render.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace},
	})
}

func AddPodMonitorWatch(c controller.Controller) error {
	return addNamespacedWatch(c, &monitoringv1.PodMonitor{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.PodMonitorsKind, APIVersion: render.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: render.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace},
	})
}

func AddPrometheusRuleWatch(c controller.Controller) error {
	return addNamespacedWatch(c, &monitoringv1.PrometheusRule{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.PrometheusRuleKind, APIVersion: render.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: render.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace},
	})
}

func AddServiceMonitorCalicoNodeWatch(c controller.Controller) error {
	return addNamespacedWatch(c, &monitoringv1.ServiceMonitor{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: render.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: render.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace},
	})
}

func AddServiceMonitorElasticsearchWatch(c controller.Controller) error {
	return addNamespacedWatch(c, &monitoringv1.ServiceMonitor{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: render.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace},
	})
}
