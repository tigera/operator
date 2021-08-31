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
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("monitor rendering tests", func() {
	It("Should render Prometheus resources", func() {
		component := render.Monitor(
			&operatorv1.InstallationSpec{},
			[]*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
			},
		)

		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()

		// should render correct resources
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-prometheus", "", "", "v1", "Namespace"},
			{"tigera-pull-secret", common.TigeraPrometheusNamespace, "", "", ""},
			{"tigera-prometheus-role", common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "Role"},
			{"tigera-prometheus-role-binding", common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding"},
			{"alertmanager-calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Secret"},
			{"calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Service"},
			{"calico-node-alertmanager", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind},
			{"prometheus", common.TigeraPrometheusNamespace, "", "v1", "ServiceAccount"},
			{"prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{"prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{"calico-node-prometheus", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind},
			{"tigera-prometheus-dp-rate", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind},
			{"calico-node-monitor", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"elasticsearch-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"fluentd-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PodMonitorsKind},
			{"prometheus-http-api", common.TigeraPrometheusNamespace, "", "v1", "Service"},
		}

		Expect(len(toCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := toCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		Expect(toDelete).To(HaveLen(1))

		obj := toDelete[0]
		rtest.ExpectResource(obj, "elasticearch-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind)
	})

	It("Should render Prometheus resource Specs correctly", func() {
		component := render.Monitor(
			&operatorv1.InstallationSpec{},
			[]*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
			},
		)

		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		// Alertmanager
		alertmanagerObj, ok := rtest.GetResource(toCreate, render.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())
		alertmanagerCom := components.ComponentPrometheusAlertmanager
		Expect(*alertmanagerObj.Spec.Image).To(Equal(fmt.Sprintf("quay.io/%s:%s", alertmanagerCom.Image, alertmanagerCom.Version)))
		Expect(*alertmanagerObj.Spec.Replicas).To(Equal(int32(3)))
		Expect(alertmanagerObj.Spec.Version).To(Equal(alertmanagerCom.Version))

		// Alertmanager Secret
		secretObj, ok := rtest.GetResource(toCreate, "alertmanager-calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue())
		Expect(secretObj.Data).To(HaveLen(1))
		expectedAlertmanagerConfig := `global:
  resolve_timeout: 5m
route:
  group_by: ['job']
  group_wait: 30s
  group_interval: 1m
  repeat_interval: 5m
  receiver: 'webhook'
receivers:
- name: 'webhook'
  webhook_configs:
  - url: 'http://calico-alertmanager-webhook:30501/'
`
		Expect(secretObj.Data["alertmanager.yaml"]).To(Equal([]byte(expectedAlertmanagerConfig)))

		// Alertmanager Service
		serviceObj, ok := rtest.GetResource(toCreate, "calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ok).To(BeTrue())
		Expect(serviceObj.Spec.Ports).To(HaveLen(1))
		Expect(serviceObj.Spec.Ports[0].Name).To(Equal("web"))
		Expect(serviceObj.Spec.Ports[0].Port).To(Equal(int32(9093)))
		Expect(serviceObj.Spec.Ports[0].Protocol).To(Equal(corev1.ProtocolTCP))
		Expect(serviceObj.Spec.Ports[0].TargetPort).To(Equal(intstr.FromString("web")))
		Expect(serviceObj.Spec.Selector).To(HaveLen(1))
		Expect(serviceObj.Spec.Selector["alertmanager"]).To(Equal("calico-node-alertmanager"))

		// Prometheus
		prometheusObj, ok := rtest.GetResource(toCreate, render.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())
		prometheusCom := components.ComponentPrometheus
		Expect(*prometheusObj.Spec.Image).To(Equal(fmt.Sprintf("quay.io/%s:%s", prometheusCom.Image, prometheusCom.Version)))
		Expect(prometheusObj.Spec.ServiceAccountName).To(Equal("prometheus"))
		Expect(prometheusObj.Spec.ServiceMonitorSelector.MatchLabels["team"]).To(Equal("network-operators"))
		Expect(prometheusObj.Spec.PodMonitorSelector.MatchLabels["team"]).To(Equal("network-operators"))
		Expect(prometheusObj.Spec.Version).To(Equal(prometheusCom.Version))
		Expect(prometheusObj.Spec.Retention).To(Equal("24h"))
		Expect(prometheusObj.Spec.Resources.Requests.Memory().Equal(resource.MustParse("400Mi"))).To(BeTrue())
		Expect(prometheusObj.Spec.RuleSelector.MatchLabels["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusObj.Spec.RuleSelector.MatchLabels["role"]).To(Equal("tigera-prometheus-rules"))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers).To(HaveLen(1))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Name).To(Equal("calico-node-alertmanager"))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Namespace).To(Equal("tigera-prometheus"))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Port).To(Equal(intstr.FromString("web")))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Scheme).To(Equal("HTTP"))

		// Prometheus ServiceAccount
		_, ok = rtest.GetResource(toCreate, "prometheus", common.TigeraPrometheusNamespace, "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
		Expect(ok).To(BeTrue())

		// Prometheus ClusterRole
		prometheusClusterRoleObj, ok := rtest.GetResource(toCreate, "prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(ok).To(BeTrue())
		Expect(prometheusClusterRoleObj.Rules).To(HaveLen(3))
		Expect(prometheusClusterRoleObj.Rules[0].APIGroups).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[0].APIGroups[0]).To(Equal(""))
		Expect(prometheusClusterRoleObj.Rules[0].Resources).To(HaveLen(4))
		Expect(prometheusClusterRoleObj.Rules[0].Resources).To(BeEquivalentTo([]string{
			"endpoints",
			"nodes",
			"pods",
			"services",
		}))
		Expect(prometheusClusterRoleObj.Rules[0].Verbs).To(HaveLen(3))
		Expect(prometheusClusterRoleObj.Rules[0].Verbs).To(BeEquivalentTo([]string{
			"get",
			"list",
			"watch",
		}))
		Expect(prometheusClusterRoleObj.Rules[1].APIGroups).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[1].APIGroups[0]).To(Equal(""))
		Expect(prometheusClusterRoleObj.Rules[1].Resources).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[1].Resources[0]).To(Equal("configmaps"))
		Expect(prometheusClusterRoleObj.Rules[1].Verbs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[1].Verbs[0]).To(Equal("get"))
		Expect(prometheusClusterRoleObj.Rules[2].NonResourceURLs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].NonResourceURLs[0]).To(Equal("/metrics"))
		Expect(prometheusClusterRoleObj.Rules[2].Verbs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].Verbs[0]).To(Equal("get"))

		// Prometheus ClusterRoleBinding
		prometheusClusterRolebindingObj, ok := rtest.GetResource(toCreate, "prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(ok).To(BeTrue())
		Expect(prometheusClusterRolebindingObj.RoleRef.APIGroup).To(Equal("rbac.authorization.k8s.io"))
		Expect(prometheusClusterRolebindingObj.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(prometheusClusterRolebindingObj.RoleRef.Name).To(Equal("prometheus"))
		Expect(prometheusClusterRolebindingObj.Subjects).To(HaveLen(1))
		Expect(prometheusClusterRolebindingObj.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(prometheusClusterRolebindingObj.Subjects[0].Name).To(Equal("prometheus"))
		Expect(prometheusClusterRolebindingObj.Subjects[0].Namespace).To(Equal(common.TigeraPrometheusNamespace))

		// Prometheus HTTP API service
		prometheusServiceObj, ok := rtest.GetResource(toCreate, render.PrometheusHTTPAPIServiceName, common.TigeraPrometheusNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ok).To(BeTrue())
		Expect(prometheusServiceObj.Spec.Selector).To(HaveLen(1))
		Expect(prometheusServiceObj.Spec.Selector["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusServiceObj.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
		Expect(prometheusServiceObj.Spec.Ports).To(HaveLen(1))
		Expect(prometheusServiceObj.Spec.Ports[0].Port).To(Equal(int32(9090)))
		Expect(prometheusServiceObj.Spec.Ports[0].TargetPort).To(Equal(intstr.FromInt(9090)))

		// PodMonitor
		podmonitorObj, ok := rtest.GetResource(toCreate, render.FluentdMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PodMonitorsKind).(*monitoringv1.PodMonitor)
		Expect(ok).To(BeTrue())
		Expect(podmonitorObj.ObjectMeta.Labels).To(HaveLen(1))
		Expect(podmonitorObj.ObjectMeta.Labels["team"]).To(Equal("network-operators"))
		Expect(podmonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(podmonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("fluentd-node"))
		Expect(podmonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(podmonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("tigera-fluentd"))
		Expect(podmonitorObj.Spec.PodMetricsEndpoints).To(HaveLen(1))
		Expect(podmonitorObj.Spec.PodMetricsEndpoints[0].HonorLabels).To(BeTrue())
		Expect(podmonitorObj.Spec.PodMetricsEndpoints[0].Interval).To(Equal("5s"))
		Expect(podmonitorObj.Spec.PodMetricsEndpoints[0].Port).To(Equal("metrics-port"))
		Expect(podmonitorObj.Spec.PodMetricsEndpoints[0].ScrapeTimeout).To(Equal("5s"))

		// PrometheusRule
		prometheusruleObj, ok := rtest.GetResource(toCreate, render.TigeraPrometheusDPRate, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind).(*monitoringv1.PrometheusRule)
		Expect(ok).To(BeTrue())
		Expect(prometheusruleObj.ObjectMeta.Labels).To(HaveLen(2))
		Expect(prometheusruleObj.ObjectMeta.Labels["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusruleObj.ObjectMeta.Labels["role"]).To(Equal("tigera-prometheus-rules"))
		Expect(prometheusruleObj.Spec.Groups).To(HaveLen(1))
		Expect(prometheusruleObj.Spec.Groups[0].Name).To(Equal("calico.rules"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules).To(HaveLen(1))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Alert).To(Equal("DeniedPacketsRate"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Expr).To(Equal(intstr.FromString("rate(calico_denied_packets[10s]) > 50")))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Labels["severity"]).To(Equal("critical"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Annotations["summary"]).To(Equal("Instance {{$labels.instance}} - Large rate of packets denied"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Annotations["description"]).To(Equal("{{$labels.instance}} with calico-node pod {{$labels.pod}} has been denying packets at a fast rate {{$labels.sourceIp}} by policy {{$labels.policy}}."))

		// ServiceMonitor
		servicemonitorObj, ok := rtest.GetResource(toCreate, render.CalicoNodeMonitor, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.ObjectMeta.Labels).To(HaveLen(1))
		Expect(servicemonitorObj.ObjectMeta.Labels["team"]).To(Equal("network-operators"))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("calico-node"))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("calico-system"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(2))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(Equal("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("calico-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(Equal("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[1].Interval).To(Equal("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].Port).To(Equal("calico-bgp-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[1].ScrapeTimeout).To(Equal("5s"))

		servicemonitorObj, ok = rtest.GetResource(toCreate, render.ElasticsearchMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("tigera-elasticsearch-metrics"))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("tigera-elasticsearch"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(Equal("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(Equal("5s"))

		// Role
		roleObj, ok := rtest.GetResource(toCreate, render.TigeraPrometheusRole, common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(ok).To(BeTrue())
		Expect(roleObj.Rules).To(HaveLen(1))
		Expect(roleObj.Rules[0].APIGroups).To(HaveLen(1))
		Expect(roleObj.Rules[0].APIGroups[0]).To(Equal("monitoring.coreos.com"))
		Expect(roleObj.Rules[0].Resources).To(HaveLen(6))
		Expect(roleObj.Rules[0].Resources).To(BeEquivalentTo([]string{
			"alertmanagers",
			"podmonitors",
			"prometheuses",
			"prometheusrules",
			"servicemonitors",
			"thanosrulers",
		}))
		Expect(roleObj.Rules[0].Verbs).To(HaveLen(6))
		Expect(roleObj.Rules[0].Verbs).To(BeEquivalentTo([]string{
			"create",
			"delete",
			"get",
			"list",
			"update",
			"watch",
		}))

		// RoleBinding
		rolebindingObj, ok := rtest.GetResource(toCreate, render.TigeraPrometheusRoleBinding, common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(ok).To(BeTrue())
		Expect(rolebindingObj.RoleRef.APIGroup).To(Equal("rbac.authorization.k8s.io"))
		Expect(rolebindingObj.RoleRef.Kind).To(Equal("Role"))
		Expect(rolebindingObj.RoleRef.Name).To(Equal(render.TigeraPrometheusRole))
		Expect(rolebindingObj.Subjects).To(HaveLen(1))
		Expect(rolebindingObj.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(rolebindingObj.Subjects[0].Name).To(Equal("tigera-operator"))
		Expect(rolebindingObj.Subjects[0].Namespace).To(Equal(rmeta.OperatorNamespace()))
	})
})
