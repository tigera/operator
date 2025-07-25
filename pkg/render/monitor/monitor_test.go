// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sresource "k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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
	expectedAlertmanagerPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager.json")
	expectedAlertmanagerMeshPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager-mesh.json")
	expectedPrometheusPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus.json")
	expectedPrometheusApiPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-api.json")
	expectedPrometheusOperatorPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-operator.json")
	expectedAlertmanagerPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager_ocp.json")
	expectedAlertmanagerMeshPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/alertmanager-mesh_ocp.json")
	expectedPrometheusPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus_ocp.json")
	expectedPrometheusApiPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-api_ocp.json")
	expectedPrometheusOperatorPolicyOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/prometheus-operator_ocp.json")

	var cfg *monitor.Config
	var prometheusKeyPair certificatemanagement.KeyPairInterface

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		prometheusKeyPair, err = certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())

		prometheusClientKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())

		bundle := certificateManager.CreateTrustedBundle()
		cfg = &monitor.Config{
			Installation: &operatorv1.InstallationSpec{
				ControlPlaneReplicas: ptr.Int32ToPtr(3),
			},
			PullSecrets: []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
			},
			ServerTLSSecret:          prometheusKeyPair,
			ClientTLSSecret:          prometheusClientKeyPair,
			AlertmanagerConfigSecret: defaultAlertmanagerConfigSecret,
			ClusterDomain:            "example.org",
			TrustedCertBundle:        bundle,
		}
	})

	It("Should render Prometheus resources", func() {
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()

		// should render correct resources
		expectedResources := expectedBaseResources()
		rtest.ExpectResources(toCreate, expectedResources)

		Expect(toDelete).To(HaveLen(3))

		// Check the namespace.
		namespace := rtest.GetResource(toCreate, "tigera-prometheus", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("baseline"))
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

		service := rtest.GetResource(toCreate, "prometheus-http-api", "tigera-prometheus", "", "v1", "Service").(*corev1.Service)
		Expect(service.Labels["k8s-app"]).To(Equal("tigera-prometheus"))
	})

	It("Should render Prometheus resources with resources requests and limits", func() {

		prometheusResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("1"),
				"memory": k8sresource.MustParse("500Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("101m"),
				"memory": k8sresource.MustParse("100Mi"),
			},
		}
		alertManagerResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("601m"),
				"memory": k8sresource.MustParse("600Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("201m"),
				"memory": k8sresource.MustParse("200Mi"),
			},
		}

		cfg.Monitor.Prometheus = &operatorv1.Prometheus{
			PrometheusSpec: &operatorv1.PrometheusSpec{
				CommonPrometheusFields: &operatorv1.CommonPrometheusFields{
					Containers: []operatorv1.PrometheusContainer{{
						Name:      "authn-proxy",
						Resources: &prometheusResources,
					},
					},
					Resources: prometheusResources,
				},
			},
		}

		cfg.Monitor.AlertManager = &operatorv1.AlertManager{
			AlertManagerSpec: &operatorv1.AlertManagerSpec{
				Resources: alertManagerResources,
			},
		}

		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		Expect(toDelete).To(HaveLen(3))

		// Prometheus
		prometheusObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())

		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers).To(HaveLen(1))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].Name).To(Equal("authn-proxy"))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].Resources).To(Equal(prometheusResources))

		Expect(prometheusObj.Spec.CommonPrometheusFields.Resources).To(Equal(prometheusResources))

		// AlertManager
		alertmanagerObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())
		Expect(alertmanagerObj.Spec.Resources).To(Equal(alertManagerResources))

	})

	It("Should render Prometheus resource Specs correctly", func() {
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		// Prometheus Operator
		_, ok := rtest.GetResource(toCreate, "calico-prometheus-operator", "tigera-prometheus", "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
		Expect(ok).To(BeTrue())
		promOperClusterRoleObj, ok := rtest.GetResource(toCreate, "calico-prometheus-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(ok).To(BeTrue())
		Expect(promOperClusterRoleObj.Rules).To(HaveLen(10))
		Expect(promOperClusterRoleObj.Rules[0]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"monitoring.coreos.com"},
			Resources: []string{
				"alertmanagers",
				"alertmanagers/finalizers",
				"alertmanagers/status",
				"alertmanagerconfigs",
				"prometheuses",
				"prometheuses/finalizers",
				"prometheuses/status",
				"prometheusagents",
				"prometheusagents/finalizers",
				"prometheusagents/status",
				"thanosrulers",
				"thanosrulers/finalizers",
				"thanosrulers/status",
				"scrapeconfigs",
				"servicemonitors",
				"podmonitors",
				"probes",
				"prometheusrules",
			},
			Verbs: []string{"*"},
		}))
		Expect(promOperClusterRoleObj.Rules[1]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"statefulsets"},
			Verbs:     []string{"*"},
		}))
		Expect(promOperClusterRoleObj.Rules[2]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{
				"configmaps",
			},
			Verbs: []string{"*"},
		}))
		Expect(promOperClusterRoleObj.Rules[3]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs: []string{
				"delete",
				"list",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[4]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{
				"services",
				"services/finalizers",
				"endpoints",
			},
			Verbs: []string{
				"get",
				"create",
				"update",
				"delete",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[5]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs: []string{
				"list",
				"watch",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[6]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[7]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs: []string{
				"patch",
				"create",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[8]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingresses"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[9]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"storage.k8s.io"},
			Resources: []string{"storageclasses"},
			Verbs: []string{
				"get",
			},
		}))
		promOperClusterRoleBindingObj, ok := rtest.GetResource(toCreate, "calico-prometheus-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(ok).To(BeTrue())
		Expect(promOperClusterRoleBindingObj.Subjects).To(HaveLen(1))
		Expect(promOperClusterRoleBindingObj.Subjects[0]).To(Equal(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      "calico-prometheus-operator",
			Namespace: "tigera-prometheus",
		}))
		Expect(promOperClusterRoleBindingObj.RoleRef).To(Equal(rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-prometheus-operator",
		}))

		// Alertmanager
		alertmanagerObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())
		alertmanagerCom := components.ComponentPrometheusAlertmanager
		Expect(*alertmanagerObj.Spec.Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, alertmanagerCom.Image, alertmanagerCom.Version)))
		Expect(*alertmanagerObj.Spec.Replicas).To(Equal(int32(3)))
		Expect(alertmanagerObj.Spec.Version).To(Equal(components.ComponentCoreOSAlertmanager.Version))
		Expect(*alertmanagerObj.Spec.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*alertmanagerObj.Spec.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*alertmanagerObj.Spec.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(alertmanagerObj.Spec.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

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
		Expect(prometheusObj.Spec.Retention).To(BeEquivalentTo("24h"))
		Expect(prometheusObj.Spec.Resources.Requests.Memory().Equal(k8sresource.MustParse("400Mi"))).To(BeTrue())
		Expect(prometheusObj.Spec.RuleSelector.MatchLabels["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusObj.Spec.RuleSelector.MatchLabels["role"]).To(Equal("tigera-prometheus-rules"))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers).To(HaveLen(1))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Name).To(Equal("calico-node-alertmanager"))
		Expect(*prometheusObj.Spec.Alerting.Alertmanagers[0].Namespace).To(Equal("tigera-prometheus"))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Port).To(Equal(intstr.FromString("web")))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Scheme).To(Equal("HTTP"))
		Expect(*prometheusObj.Spec.ReloadStrategy).To(BeEquivalentTo(monitoringv1.ProcessSignalReloadStrategyType))
		Expect(*prometheusObj.Spec.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*prometheusObj.Spec.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*prometheusObj.Spec.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(prometheusObj.Spec.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers).To(HaveLen(1))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].Name).To(Equal("authn-proxy"))
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// Prometheus ServiceAccount
		_, ok = rtest.GetResource(toCreate, "prometheus", common.TigeraPrometheusNamespace, "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
		Expect(ok).To(BeTrue())

		// Prometheus ClusterRole
		prometheusClusterRoleObj, ok := rtest.GetResource(toCreate, "prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(ok).To(BeTrue())
		Expect(prometheusClusterRoleObj.Rules).To(HaveLen(4))
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
		Expect(prometheusClusterRoleObj.Rules[2].APIGroups).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].APIGroups[0]).To(Equal(""))
		Expect(prometheusClusterRoleObj.Rules[2].Resources).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].Resources[0]).To(Equal("services/proxy"))
		Expect(prometheusClusterRoleObj.Rules[2].ResourceNames).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].ResourceNames[0]).To(Equal("https:calico-api:8080"))
		Expect(prometheusClusterRoleObj.Rules[2].Verbs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].Verbs[0]).To(Equal("get"))
		Expect(prometheusClusterRoleObj.Rules[3].NonResourceURLs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[3].NonResourceURLs[0]).To(Equal("/metrics"))
		Expect(prometheusClusterRoleObj.Rules[3].Verbs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[3].Verbs[0]).To(Equal("get"))

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
		prometheusServiceObj, ok := rtest.GetResource(toCreate, "prometheus-http-api", common.TigeraPrometheusNamespace, "", "v1", "Service").(*corev1.Service)
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
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(0))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(ConsistOf([]metav1.LabelSelectorRequirement{
			{
				Key:      "k8s-app",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"fluentd-node", "fluentd-node-windows"},
			},
		}))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("tigera-fluentd"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("fluentd-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))

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
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(0))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(ConsistOf([]metav1.LabelSelectorRequirement{
			{Key: "k8s-app",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"calico-node", "calico-node-windows"}},
		}))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("calico-system"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(2))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("calico-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Scheme).To(Equal("https"))
		Expect(servicemonitorObj.Spec.Endpoints[1].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[1].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].Port).To(Equal("calico-bgp-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[1].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].Scheme).To(Equal("https"))

		servicemonitorObj, ok = rtest.GetResource(toCreate, monitor.ElasticsearchMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("tigera-elasticsearch-metrics"))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("tigera-elasticsearch"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Scheme).To(Equal("https"))

		servicemonitorObj, ok = rtest.GetResource(toCreate, "fluentd-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(0))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(ConsistOf([]metav1.LabelSelectorRequirement{
			{
				Key:      "k8s-app",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"fluentd-node", "fluentd-node-windows"},
			},
		}))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("tigera-fluentd"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("fluentd-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Scheme).To(Equal("https"))

		servicemonitorObj, ok = rtest.GetResource(toCreate, "calico-api", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("calico-api"))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("calico-system"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("queryserver"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Scheme).To(Equal("https"))
		//nolint:staticcheck // Ignore SA1019 deprecated
		Expect(servicemonitorObj.Spec.Endpoints[0].BearerTokenFile).To(Equal("/var/run/secrets/kubernetes.io/serviceaccount/token"))

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

	It("should render toleration on GKE", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		prometheusObj, ok := rtest.GetResource(resources, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())
		alertmanagerObj, ok := rtest.GetResource(resources, monitor.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())

		Expect(prometheusObj.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
		Expect(alertmanagerObj.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "calico-prometheus-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))

		role = rtest.GetResource(resources, "prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))

		role = rtest.GetResource(resources, "tigera-prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	It("Should render Prometheus resources when Dex is enabled", func() {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain:  "https://127.0.0.1",
				GroupsPrefix:   "g:",
				UsernamePrefix: "u:",
				OIDC:           &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email", GroupsClaim: "grp"},
			},
		}

		dexCfg := render.NewDexKeyValidatorConfig(authentication,
			nil,
			dns.DefaultClusterDomain)
		cfg.KeyValidatorConfig = dexCfg
		cfg.ServerTLSSecret = prometheusKeyPair
		component := monitor.Monitor(cfg)

		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		rtest.ExpectResources(toCreate, expectedResources)

		Expect(toDelete).To(HaveLen(3))

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
				Name:      "TLS_KEY",
				Value:     "/calico-node-prometheus-tls/tls.key",
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CERT",
				Value:     "/calico-node-prometheus-tls/tls.crt",
				ValueFrom: nil,
			},

			{
				Name:      "TLS_SERVER_SECRET_HASH_ANNOTATION",
				Value:     prometheusKeyPair.HashAnnotationValue(),
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CLIENT_SECRET_HASH_ANNOTATION",
				Value:     cfg.ClientTLSSecret.HashAnnotationValue(),
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CA_BUNDLE_HASH_ANNOTATION",
				Value:     rmeta.AnnotationHash(cfg.TrustedCertBundle.HashAnnotations()),
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

	Context("allow-tigera rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "allow-tigera.calico-node-alertmanager", Namespace: "tigera-prometheus"},
			{Name: "allow-tigera.calico-node-alertmanager-mesh", Namespace: "tigera-prometheus"},
			{Name: "allow-tigera.prometheus", Namespace: "tigera-prometheus"},
			{Name: "allow-tigera.tigera-prometheus-api", Namespace: "tigera-prometheus"},
			{Name: "allow-tigera.prometheus-operator", Namespace: "tigera-prometheus"},
		}

		getExpectedPolicy := func(name types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if name.Name == "allow-tigera.calico-node-alertmanager" {
				return testutils.SelectPolicyByProvider(scenario, expectedAlertmanagerPolicy, expectedAlertmanagerPolicyForOpenshift)
			} else if name.Name == "allow-tigera.calico-node-alertmanager-mesh" {
				return testutils.SelectPolicyByProvider(scenario, expectedAlertmanagerMeshPolicy, expectedAlertmanagerMeshPolicyForOpenshift)
			} else if name.Name == "allow-tigera.prometheus" {
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusPolicy, expectedPrometheusPolicyForOpenshift)
			} else if name.Name == "allow-tigera.tigera-prometheus-api" {
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusApiPolicy, expectedPrometheusApiPolicyForOpenshift)
			} else if name.Name == "allow-tigera.prometheus-operator" {
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusOperatorPolicy, expectedPrometheusOperatorPolicyOpenshift)
			}

			return nil
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.OpenShift = scenario.OpenShift
				cfg.KubeControllerPort = 9094

				component := monitor.MonitorPolicy(cfg)
				resourcesToCreate, _ := component.Objects()

				for _, policyName := range policyNames {
					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: true}),
		)

		It("prometheus policy should omit kube-controller egress rule when kube-controller port is 0", func() {
			// Baseline case
			cfg.KubeControllerPort = 9094
			component := monitor.MonitorPolicy(cfg)
			resourcesToCreate, _ := component.Objects()
			baselinePolicy := testutils.GetAllowTigeraPolicyFromResources(types.NamespacedName{Name: "allow-tigera.prometheus", Namespace: "tigera-prometheus"}, resourcesToCreate)

			// kube-controllers port set to 0
			cfg.KubeControllerPort = 0
			component = monitor.MonitorPolicy(cfg)
			resourcesToCreate, _ = component.Objects()
			zeroedPolicy := testutils.GetAllowTigeraPolicyFromResources(types.NamespacedName{Name: "allow-tigera.prometheus", Namespace: "tigera-prometheus"}, resourcesToCreate)

			Expect(len(zeroedPolicy.Spec.Egress)).To(Equal(len(baselinePolicy.Spec.Egress) - 1))
		})
	})

	It("Should render external prometheus resources with service monitor", func() {
		cfg.Monitor.ExternalPrometheus = &operatorv1.ExternalPrometheus{
			ServiceMonitor: &operatorv1.ServiceMonitor{
				Endpoints: []operatorv1.Endpoint{
					{
						BearerTokenSecret: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-external-prometheus"},
						},
					},
				},
			},
			Namespace: "external-prometheus",
		}
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(3))
	})

	It("Should render external prometheus resources with service monitor and custom token", func() {
		cfg.Monitor.ExternalPrometheus = &operatorv1.ExternalPrometheus{
			ServiceMonitor: &operatorv1.ServiceMonitor{
				Endpoints: []operatorv1.Endpoint{
					{
						BearerTokenSecret: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "some-other-token"},
						},
					},
				},
			},
			Namespace: "external-prometheus",
		}
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(3))
	})

	It("Should render external prometheus resources without service monitor", func() {
		cfg.Monitor.ExternalPrometheus = &operatorv1.ExternalPrometheus{
			Namespace: "external-prometheus",
		}
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(3))
	})

	It("Should render typha service monitor if typha metrics are enabled", func() {
		cfg.Installation.TyphaMetricsPort = ptr.Int32ToPtr(9093)
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-typha-metrics", Namespace: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(2))
		sm := rtest.GetResource(toCreate, "calico-typha-metrics", "tigera-prometheus", "monitoring.coreos.com", "v1", "ServiceMonitor").(*monitoringv1.ServiceMonitor)
		Expect(sm).To(Equal(&monitoringv1.ServiceMonitor{
			TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: "monitoring.coreos.com/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-typha-metrics",
				Namespace: "tigera-prometheus",
				Labels:    map[string]string{"team": "network-operators"},
			},
			Spec: monitoringv1.ServiceMonitorSpec{
				Endpoints: []monitoringv1.Endpoint{
					{
						HonorLabels:   true,
						Interval:      "5s",
						Port:          "calico-typha-metrics",
						Scheme:        "http",
						ScrapeTimeout: "5s",
					},
				},
				NamespaceSelector: monitoringv1.NamespaceSelector{
					MatchNames: []string{common.CalicoNamespace},
				},
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						render.AppLabelName: render.TyphaMetricsName,
					},
				},
			},
		}))
	})

	It("Should render serviceMonitor with felix endpoint if FelixPrometheusMetricsEnabled", func() {
		cfg.FelixPrometheusMetricsEnabled = true
		component := monitor.Monitor(cfg)
		toCreate, _ := component.Objects()
		servicemonitorObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodeMonitor, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())

		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(3))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("calico-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Scheme).To(Equal("https"))
		Expect(servicemonitorObj.Spec.Endpoints[1].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[1].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].Port).To(Equal("calico-bgp-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[1].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].Scheme).To(Equal("https"))
		Expect(servicemonitorObj.Spec.Endpoints[2].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[2].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[2].Port).To(Equal("felix-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[2].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[2].Scheme).To(Equal("http"))

	})
})

// expectedBaseResources These are the expected resources in the most basic setup.
func expectedBaseResources() []client.Object {
	return []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus-role", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator-secret", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus-role-binding", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator-secret", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-calico-node-alertmanager", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator", Namespace: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "prometheus", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&monitoringv1.Prometheus{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-prometheus", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Prometheus", APIVersion: "monitoring.coreos.com/v1"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-alertmanager", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
		&monitoringv1.Alertmanager{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-alertmanager", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Alertmanager", APIVersion: "monitoring.coreos.com/v1"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-http-api", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&monitoringv1.PrometheusRule{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus-dp-rate", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-monitor", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "elasticsearch-metrics", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "fluentd-metrics", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers-metrics", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
	}
}
