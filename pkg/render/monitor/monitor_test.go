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

package monitor_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/monitor"
)

var _ = Describe("monitor rendering tests", func() {
	defaultAlertmanagerConfigSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.AlertmanagerConfigSecret,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string][]byte{
			"alertmanager.yaml": []byte("Alertmanager configuration secret"),
		},
	}

	var cfg *monitor.Config

	BeforeEach(func() {
		cfg = &monitor.Config{
			Installation: &operatorv1.InstallationSpec{},
			PullSecrets: []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
			},
			ServerTLSSecret: &corev1.Secret{
				TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: monitor.PrometheusTLSSecretName, Namespace: common.OperatorNamespace()}},
			ClientTLSSecret: &corev1.Secret{
				TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: monitor.PrometheusClientTLSSecretName, Namespace: common.OperatorNamespace()}},
			TrustedCertBundle: &corev1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: render.PrometheusCABundle, Namespace: common.TigeraPrometheusNamespace}},
			AlertmanagerConfigSecret: defaultAlertmanagerConfigSecret,
			ClusterDomain:            "example.org",
		}
	})

	It("Should render Prometheus resources", func() {
		component := monitor.Monitor(cfg)
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
			{render.PrometheusCABundle, common.TigeraPrometheusNamespace, "", "v1", "ConfigMap"},
			{"tigera-prometheus-role", common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "Role"},
			{"tigera-prometheus-role-binding", common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding"},
			{"tigera-pull-secret", common.TigeraPrometheusNamespace, "", "", ""},
			{"alertmanager-calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Secret"},
			{monitor.PrometheusTLSSecretName, common.TigeraPrometheusNamespace, "", "v1", "Secret"},
			{monitor.PrometheusClientTLSSecretName, common.TigeraPrometheusNamespace, "", "v1", "Secret"},
			{"calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Service"},
			{"calico-node-alertmanager", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind},
			{"prometheus", common.TigeraPrometheusNamespace, "", "v1", "ServiceAccount"},
			{"prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{"prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{"calico-node-prometheus", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind},
			{"tigera-prometheus-dp-rate", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind},
			{"calico-node-monitor", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"elasticsearch-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"fluentd-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"prometheus-http-api", common.TigeraPrometheusNamespace, "", "v1", "Service"},
			{name: monitor.TigeraPrometheusObjectName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: monitor.TigeraPrometheusObjectName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		Expect(len(toCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := toCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		Expect(toDelete).To(HaveLen(2))

		obj := toDelete[0]
		rtest.ExpectResource(obj, "elasticearch-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind)
	})

	It("Should render Prometheus resource Specs correctly", func() {
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		// Alertmanager
		alertmanagerObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())
		alertmanagerCom := components.ComponentPrometheusAlertmanager
		Expect(*alertmanagerObj.Spec.Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, alertmanagerCom.Image, alertmanagerCom.Version)))
		Expect(*alertmanagerObj.Spec.Replicas).To(Equal(int32(3)))
		Expect(alertmanagerObj.Spec.Version).To(Equal(components.ComponentCoreOSAlertmanager.Version))

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

		// Alertmanager configuration secret
		secretObj, ok := rtest.GetResource(toCreate, "alertmanager-calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue())
		Expect(secretObj.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager configuration secret")))

		// Prometheus
		prometheusObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())
		prometheusCom := components.ComponentPrometheus
		Expect(*prometheusObj.Spec.Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, prometheusCom.Image, prometheusCom.Version)))
		Expect(prometheusObj.Spec.ServiceAccountName).To(Equal("prometheus"))
		Expect(prometheusObj.Spec.ServiceMonitorSelector.MatchLabels["team"]).To(Equal("network-operators"))
		Expect(prometheusObj.Spec.PodMonitorSelector.MatchLabels["team"]).To(Equal("network-operators"))
		Expect(prometheusObj.Spec.Version).To(Equal(components.ComponentCoreOSPrometheus.Version))
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
		Expect(prometheusClusterRolebindingObj.Subjects[0].Namespace).To(Equal("tigera-prometheus"))

		// Prometheus HTTP API service
		prometheusServiceObj, ok := rtest.GetResource(toCreate, monitor.PrometheusHTTPAPIServiceName, common.TigeraPrometheusNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ok).To(BeTrue())
		Expect(prometheusServiceObj.Spec.Selector).To(HaveLen(1))
		Expect(prometheusServiceObj.Spec.Selector["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusServiceObj.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
		Expect(prometheusServiceObj.Spec.Ports).To(HaveLen(1))
		Expect(prometheusServiceObj.Spec.Ports[0].Port).To(Equal(int32(9090)))
		Expect(prometheusServiceObj.Spec.Ports[0].TargetPort).To(Equal(intstr.FromInt(9095)))

		// PodMonitor
		servicemonitorObj, ok := rtest.GetResource(toCreate, monitor.FluentdMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.ObjectMeta.Labels).To(HaveLen(1))
		Expect(servicemonitorObj.ObjectMeta.Labels["team"]).To(Equal("network-operators"))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("fluentd-node"))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("tigera-fluentd"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(Equal("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("fluentd-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(Equal("5s"))

		// PrometheusRule
		prometheusruleObj, ok := rtest.GetResource(toCreate, monitor.TigeraPrometheusDPRate, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind).(*monitoringv1.PrometheusRule)
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
		servicemonitorObj, ok = rtest.GetResource(toCreate, monitor.CalicoNodeMonitor, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
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

		servicemonitorObj, ok = rtest.GetResource(toCreate, monitor.ElasticsearchMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
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
		roleObj, ok := rtest.GetResource(toCreate, monitor.TigeraPrometheusRole, common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
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
		rolebindingObj, ok := rtest.GetResource(toCreate, monitor.TigeraPrometheusRoleBinding, common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(ok).To(BeTrue())
		Expect(rolebindingObj.RoleRef.APIGroup).To(Equal("rbac.authorization.k8s.io"))
		Expect(rolebindingObj.RoleRef.Kind).To(Equal("Role"))
		Expect(rolebindingObj.RoleRef.Name).To(Equal("tigera-prometheus-role"))
		Expect(rolebindingObj.Subjects).To(HaveLen(1))
		Expect(rolebindingObj.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(rolebindingObj.Subjects[0].Name).To(Equal("tigera-operator"))
		Expect(rolebindingObj.Subjects[0].Namespace).To(Equal(common.OperatorNamespace()))
	})

	It("Should render Prometheus resources when Dex is enabled", func() {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain:  "https://127.0.0.1",
				GroupsPrefix:   "g:",
				UsernamePrefix: "u:",
				OIDC:           &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email", GroupsClaim: "grp"}}}

		dexCfg := render.NewDexKeyValidatorConfig(authentication,
			nil,
			&corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.DexTLSSecretName,
					Namespace: common.OperatorNamespace(),
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("cert"),
					corev1.TLSPrivateKeyKey: []byte("key"),
				},
			},
			dns.DefaultClusterDomain)
		cfg.KeyValidatorConfig = dexCfg
		cfg.ServerTLSSecret = &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      monitor.PrometheusTLSSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       []byte("cert"),
				corev1.TLSPrivateKeyKey: []byte("key"),
			},
		}
		component := monitor.Monitor(cfg)

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
			{render.PrometheusCABundle, common.TigeraPrometheusNamespace, "", "v1", "ConfigMap"},
			{"tigera-prometheus-role", common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "Role"},
			{"tigera-prometheus-role-binding", common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding"},
			{"tigera-pull-secret", common.TigeraPrometheusNamespace, "", "", ""},
			{"alertmanager-calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Secret"},
			{monitor.PrometheusTLSSecretName, common.TigeraPrometheusNamespace, "", "v1", "Secret"},
			{monitor.PrometheusClientTLSSecretName, common.TigeraPrometheusNamespace, "", "v1", "Secret"},
			{"calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Service"},
			{"calico-node-alertmanager", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind},
			{"prometheus", common.TigeraPrometheusNamespace, "", "v1", "ServiceAccount"},
			{"prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{"prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{"calico-node-prometheus", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind},
			{"tigera-prometheus-dp-rate", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind},
			{"calico-node-monitor", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"elasticsearch-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"fluentd-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind},
			{"prometheus-http-api", common.TigeraPrometheusNamespace, "", "v1", "Service"},
			{monitor.TigeraPrometheusObjectName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole"},
			{monitor.TigeraPrometheusObjectName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
			{name: "tigera-dex-tls", ns: common.TigeraPrometheusNamespace, group: "", version: "v1", kind: "Secret"},
		}

		Expect(len(toCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := toCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		Expect(toDelete).To(HaveLen(2))

		// Prometheus
		prometheusObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())
		prometheusCom := components.ComponentPrometheus
		Expect(*prometheusObj.Spec.Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, prometheusCom.Image, prometheusCom.Version)))
		Expect(prometheusObj.Spec.Containers).To(HaveLen(1))
		proxy := prometheusObj.Spec.Containers[0]
		Expect(proxy.Env).To(ConsistOf([]corev1.EnvVar{
			{
				Name:      "PROMETHEUS_ENDPOINT_URL",
				Value:     "http://localhost:9090",
				ValueFrom: nil,
			},
			{
				Name:      "LISTEN_ADDR",
				Value:     ":9095",
				ValueFrom: nil,
			},
			{
				Name:      "TLS_SERVER_SECRET_HASH_ANNOTATION",
				Value:     "f09a0e0667b55a79c84a46b17ff28e4683cd072f",
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CLIENT_SECRET_HASH_ANNOTATION",
				Value:     "0e6ae3fec848d64b4647532abed2256acca56b85",
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CA_BUNDLE_HASH_ANNOTATION",
				Value:     "0e6ae3fec848d64b4647532abed2256acca56b85",
				ValueFrom: nil,
			},
			{
				Name:      "DEX_ENABLED",
				Value:     "true",
				ValueFrom: nil,
			},
			{
				Name:      "DEX_URL",
				Value:     "https://tigera-dex.tigera-dex.svc.cluster.local:5556/",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_ENABLED",
				Value:     "true",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_ISSUER",
				Value:     "https://127.0.0.1/dex",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_JWKSURL",
				Value:     "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_CLIENT_ID",
				Value:     "tigera-manager",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_USERNAME_CLAIM",
				Value:     "email",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_GROUPS_CLAIM",
				Value:     "groups",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_USERNAME_PREFIX",
				Value:     "u:",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_GROUPS_PREFIX",
				Value:     "g:",
				ValueFrom: nil,
			},
		}))
	})
})
