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
	rbacv1 "k8s.io/api/rbac/v1"
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
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	MonitoringAPIVersion = "monitoring.coreos.com/v1"

	CalicoNodeAlertmanager      = "calico-node-alertmanager"
	CalicoNodeMonitor           = "calico-node-monitor"
	CalicoNodePrometheus        = "calico-node-prometheus"
	ElasticsearchMetrics        = "elasticearch-metrics"
	FluentdMetrics              = "fluentd-metrics"
	TigeraPrometheusDPRate      = "tigera-prometheus-dp-rate"
	TigeraPrometheusRole        = "tigera-prometheus-role"
	TigeraPrometheusRoleBinding = "tigera-prometheus-role-binding"
)

func Monitor(
	installation *operatorv1.InstallationSpec,
	pullSecrets []*corev1.Secret,
) Component {
	return &monitorComponent{
		installation: installation,
		pullSecrets:  pullSecrets,
	}
}

type monitorComponent struct {
	installation      *operatorv1.InstallationSpec
	pullSecrets       []*corev1.Secret
	alertmanagerImage string
	prometheusImage   string
}

func (mc *monitorComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := mc.installation.Registry
	path := mc.installation.ImagePath
	prefix := mc.installation.ImagePrefix

	errMsgs := []string{}
	var err error

	mc.alertmanagerImage, err = components.GetReference(components.ComponentPrometheusAlertmanager, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	mc.prometheusImage, err = components.GetReference(components.ComponentPrometheus, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (mc *monitorComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (mc *monitorComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		createNamespace(common.TigeraPrometheusNamespace, mc.installation.KubernetesProvider),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(common.TigeraPrometheusNamespace, mc.pullSecrets...)...)...)

	objs = append(objs,
		mc.role(),
		mc.roleBinding(),
		mc.alertmanager(),
		mc.prometheus(),
		mc.prometheusRule(),
		mc.serviceMonitorCalicoNode(),
		mc.serviceMonitorElasicsearch(),
		mc.podMonitor(),
	)

	return objs, nil
}

func (mc *monitorComponent) Ready() bool {
	return true
}

func (mc *monitorComponent) alertmanager() *monitoringv1.Alertmanager {
	return &monitoringv1.Alertmanager{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.AlertmanagersKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeAlertmanager,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.AlertmanagerSpec{
			Image:            &mc.alertmanagerImage,
			ImagePullSecrets: secret.GetReferenceList(mc.pullSecrets),
			Replicas:         ptr.Int32ToPtr(3),
			Version:          components.ComponentPrometheusAlertmanager.Version,
		},
	}
}

func (mc *monitorComponent) prometheus() *monitoringv1.Prometheus {
	return &monitoringv1.Prometheus{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.PrometheusesKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodePrometheus,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.PrometheusSpec{
			Image:                  &mc.prometheusImage,
			ImagePullSecrets:       secret.GetReferenceList(mc.pullSecrets),
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

func (mc *monitorComponent) podMonitor() *monitoringv1.PodMonitor {
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

func (mc *monitorComponent) prometheusRule() *monitoringv1.PrometheusRule {
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

func (mc *monitorComponent) serviceMonitorCalicoNode() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeMonitor,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{"calico-system"}},
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

func (mc *monitorComponent) serviceMonitorElasicsearch() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetrics,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "tigera-elasticsearch-metrics"}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{"tigera-elasticsearch"}},
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

func (mc *monitorComponent) role() *rbacv1.Role {
	// list and watch have to be cluster scopes for watches to work.
	// In controller-runtime, watches are by default non-namespaced.
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraPrometheusRole,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"monitoring.coreos.com"},
				Resources: []string{
					"alertmanagers",
					"podmonitors",
					"prometheuses",
					"prometheusrules",
					"servicemonitors",
					"thanosrulers",
				},
				Verbs: []string{
					"create",
					"delete",
					"get",
					"list",
					"update",
					"watch",
				},
			},
		},
	}
}

func (mc *monitorComponent) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraPrometheusRoleBinding,
			Namespace: common.TigeraPrometheusNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     TigeraPrometheusRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-operator",
				Namespace: rmeta.OperatorNamespace(),
			},
		},
	}
}
