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

package render

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	MonitoringAPIVersion = "monitoring.coreos.com/v1"

	CalicoNodeAlertmanager = "calico-node-alertmanager"
	CalicoNodeMonitor      = "calico-node-monitor"
	CalicoNodePrometheus   = "calico-node-prometheus"
	ElasticsearchMetrics   = "elasticearch-metrics"
	FluentdMetrics         = "fluentd-metrics"
	TigeraPrometheusDPRate = "tigera-prometheus-dp-rate"
)

func Monitoring(
	installation *operatorv1.InstallationSpec,
) Component {
	return &monitoringComponent{
		installation: installation,
	}
}

type monitoringComponent struct {
	installation      *operatorv1.InstallationSpec
	alertmanagerImage string
	prometheusImage   string
}

func (mc *monitoringComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := mc.installation.Registry
	path := mc.installation.ImagePath

	errMsgs := []string{}
	var err error

	mc.alertmanagerImage, err = components.GetReference(components.ComponentPrometheusAlertmanager, reg, path, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	mc.prometheusImage, err = components.GetReference(components.ComponentPrometheus, reg, path, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (mc *monitoringComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (mc *monitoringComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		mc.alertmanager(),
		mc.prometheus(),
		mc.prometheusRule(),
		mc.serviceMonitorCalicoNode(),
		mc.serviceMonitorElasicsearch(),
		mc.podMonitor(),
	}

	return objs, nil
}

func (mc *monitoringComponent) Ready() bool {
	return true
}

func (mc *monitoringComponent) alertmanager() *monitoringv1.Alertmanager {
	return &monitoringv1.Alertmanager{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.AlertmanagersKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeAlertmanager,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.AlertmanagerSpec{
			Image:        &components.ComponentPrometheusAlertmanager.Image,
			NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
			Replicas:     ptr.Int32ToPtr(3),
			Version:      components.ComponentPrometheusAlertmanager.Version,
		},
	}
}

func (mc *monitoringComponent) prometheus() *monitoringv1.Prometheus {
	return &monitoringv1.Prometheus{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.PrometheusesKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodePrometheus,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.PrometheusSpec{
			Image:                  &components.ComponentPrometheus.Image,
			NodeSelector:           map[string]string{"kubernetes.io/os": "linux"},
			ServiceAccountName:     "prometheus",
			ServiceMonitorSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "network-operators"}},
			PodMonitorSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"team": "network-operators"}},
			Version:                components.ComponentPrometheus.Version,
			Retention:              "24h",
			Resources:              corev1.ResourceRequirements{Requests: corev1.ResourceList{"memory": resource.MustParse("400Mi")}},
			RuleSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"prometheus": CalicoNodePrometheus,
				"role":       "tigera-prometheus-rules",
			}},
			Alerting: &monitoringv1.AlertingSpec{
				Alertmanagers: []monitoringv1.AlertmanagerEndpoints{
					{
						Name:      CalicoNodeAlertmanager,
						Namespace: common.TigeraPrometheusNamespace,
						Port:      intstr.FromString("web"),
						Scheme:    string(corev1.URISchemeHTTP),
					},
				},
			},
		},
	}
}

func (mc *monitoringComponent) podMonitor() *monitoringv1.PodMonitor {
	return &monitoringv1.PodMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.PodMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentdMetrics,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.PodMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "fluentd-node"}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{"tigera-fluentd"}},
			PodMetricsEndpoints: []monitoringv1.PodMetricsEndpoint{
				{
					HonorLabels:   true,
					Interval:      "5s",
					Port:          "metrics-port",
					ScrapeTimeout: "5s",
				},
			},
		},
	}
}

func (mc *monitoringComponent) prometheusRule() *monitoringv1.PrometheusRule {
	return &monitoringv1.PrometheusRule{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.PrometheusRuleKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraPrometheusDPRate,
			Namespace: common.TigeraPrometheusNamespace,
			Labels: map[string]string{
				"prometheus": CalicoNodePrometheus,
				"role":       "tigera-prometheus-rules",
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "calico.rules",
					Rules: []monitoringv1.Rule{
						{
							Alert:  "DeniedPacketsRate",
							Expr:   intstr.FromString("rate(calico_denied_packets[10s]) > 50"),
							Labels: map[string]string{"severity": "critical"},
							Annotations: map[string]string{
								"summary":     "Instance {{$labels.instance}} - Large rate of packets denied",
								"description": "{{$labels.instance}} with calico-node pod {{$labels.pod}} has been denying packets at a fast rate {{$labels.sourceIp}} by policy {{$labels.policy}}.",
							},
						},
					},
				},
			},
		},
	}
}

func (mc *monitoringComponent) serviceMonitorCalicoNode() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeMonitor,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{"calico-node"}},
			Endpoints: []monitoringv1.Endpoint{
				{
					HonorLabels:   true,
					Interval:      "5s",
					Port:          "calico-metrics-port",
					ScrapeTimeout: "5s",
				},
				{
					HonorLabels:   true,
					Interval:      "5s",
					Port:          "calico-bgp-metrics-port",
					ScrapeTimeout: "5s",
				},
			},
		},
	}
}

func (mc *monitoringComponent) serviceMonitorElasicsearch() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetrics,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "fluentd-node"}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{"tigera-fluentd"}},
			Endpoints: []monitoringv1.Endpoint{
				{
					HonorLabels:   true,
					Interval:      "5s",
					Port:          "metrics-port",
					ScrapeTimeout: "5s",
				},
			},
		},
	}
}
