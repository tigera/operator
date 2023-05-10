// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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

package monitor

import (
	_ "embed"
	"fmt"
	"strings"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	MonitoringAPIVersion   = "monitoring.coreos.com/v1"
	CalicoNodeAlertmanager = "calico-node-alertmanager"
	CalicoNodeMonitor      = "calico-node-monitor"
	CalicoNodePrometheus   = "calico-node-prometheus"

	CalicoPrometheusOperator = "calico-prometheus-operator"

	TigeraPrometheusObjectName            = "tigera-prometheus"
	TigeraPrometheusDPRate                = "tigera-prometheus-dp-rate"
	TigeraPrometheusRole                  = "tigera-prometheus-role"
	TigeraPrometheusRoleBinding           = "tigera-prometheus-role-binding"
	TigeraPrometheusPodSecurityPolicyName = "tigera-prometheus"

	PrometheusAPIPolicyName       = networkpolicy.TigeraComponentPolicyPrefix + "tigera-prometheus-api"
	PrometheusClientTLSSecretName = "calico-node-prometheus-client-tls"
	PrometheusClusterRoleName     = "prometheus"
	PrometheusDefaultPort         = 9090
	PrometheusServiceServiceName  = "prometheus-http-api"
	PrometheusOperatorPolicyName  = networkpolicy.TigeraComponentPolicyPrefix + "prometheus-operator"
	PrometheusPolicyName          = networkpolicy.TigeraComponentPolicyPrefix + "prometheus"
	PrometheusProxyPort           = 9095
	PrometheusServiceAccountName  = "prometheus"
	PrometheusTLSSecretName       = "calico-node-prometheus-tls"

	AlertManagerPolicyName     = networkpolicy.TigeraComponentPolicyPrefix + CalicoNodeAlertmanager
	AlertmanagerConfigSecret   = "alertmanager-calico-node-alertmanager"
	AlertmanagerPort           = 9093
	MeshAlertManagerPolicyName = AlertManagerPolicyName + "-mesh"

	ElasticsearchMetrics = "elasticsearch-metrics"
	FluentdMetrics       = "fluentd-metrics"

	calicoNodePrometheusServiceName       = "calico-node-prometheus"
	tigeraPrometheusServiceHealthEndpoint = "/health"

	bearerTokenFile       = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	KubeControllerMetrics = "calico-kube-controllers-metrics"
)

var alertManagerSelector = fmt.Sprintf(
	"(app == 'alertmanager' && alertmanager == '%[1]s') || (app.kubernetes.io/name == 'alertmanager' && alertmanager == '%[1]s')",
	CalicoNodeAlertmanager,
)

func Monitor(cfg *Config) render.Component {
	return &monitorComponent{
		cfg: cfg,
	}
}

func MonitorPolicy(cfg *Config) render.Component {
	return render.NewPassthrough(
		allowTigeraAlertManagerPolicy(cfg),
		allowTigeraAlertManagerMeshPolicy(cfg),
		allowTigeraPrometheusPolicy(cfg),
		allowTigeraPrometheusAPIPolicy(cfg),
		allowTigeraPrometheusOperatorPolicy(cfg),
		networkpolicy.AllowTigeraDefaultDeny(common.TigeraPrometheusNamespace),
	)
}

// Config contains all the config information needed to render the Monitor component.
type Config struct {
	Installation             *operatorv1.InstallationSpec
	PullSecrets              []*corev1.Secret
	AlertmanagerConfigSecret *corev1.Secret
	KeyValidatorConfig       authentication.KeyValidatorConfig
	ServerTLSSecret          certificatemanagement.KeyPairInterface
	ClientTLSSecret          certificatemanagement.KeyPairInterface
	ClusterDomain            string
	TrustedCertBundle        certificatemanagement.TrustedBundle
	Openshift                bool
	KubeControllerPort       int
	UsePSP                   bool
}

type monitorComponent struct {
	cfg                    *Config
	alertmanagerImage      string
	prometheusImage        string
	prometheusServiceImage string
}

func (mc *monitorComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := mc.cfg.Installation.Registry
	path := mc.cfg.Installation.ImagePath
	prefix := mc.cfg.Installation.ImagePrefix

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

	mc.prometheusServiceImage, err = components.GetReference(components.ComponentTigeraPrometheusService, reg, path, prefix, is)
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
	toCreate := []client.Object{
		// We create the namespace with "privileged" security context because the containers deployed by the prometheus operator
		// do not set the following:
		// - securityContext.allowPrivilegeEscalation=false
		// - securityContext.capabilities.drop=["ALL"]
		// - securityContext.runAsNonRoot=true
		// - securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost"
		render.CreateNamespace(common.TigeraPrometheusNamespace, mc.cfg.Installation.KubernetesProvider, render.PSSBaseline),
	}

	// Create role and role bindings first.
	// Operator needs the create/update roles for Alertmanager configuration secret for example.
	toCreate = append(toCreate,
		mc.operatorRole(),
		mc.operatorRoleBinding(),
	)

	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(common.TigeraPrometheusNamespace, mc.cfg.PullSecrets...)...)...)
	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(common.TigeraPrometheusNamespace, mc.cfg.AlertmanagerConfigSecret)...)...)

	toCreate = append(toCreate,
		mc.prometheusOperatorServiceAccount(),
		mc.prometheusOperatorClusterRole(),
		mc.prometheusOperatorClusterRoleBinding(),
		mc.prometheusServiceAccount(),
		mc.prometheusClusterRole(),
		mc.prometheusClusterRoleBinding(),
		mc.prometheus(),
		mc.alertmanagerService(),
		mc.alertmanager(),
		mc.prometheusServiceService(),
		mc.prometheusServiceClusterRole(),
		mc.prometheusServiceClusterRoleBinding(),
		mc.prometheusRule(),
		mc.serviceMonitorCalicoNode(),
		mc.serviceMonitorElasticsearch(),
		mc.serviceMonitorFluentd(),
		mc.serviceMonitorQueryServer(),
		mc.serviceMonitorCalicoKubeControllers(),
	)

	if mc.cfg.KeyValidatorConfig != nil {
		toCreate = append(toCreate, secret.ToRuntimeObjects(mc.cfg.KeyValidatorConfig.RequiredSecrets(common.TigeraPrometheusNamespace)...)...)
		toCreate = append(toCreate, configmap.ToRuntimeObjects(mc.cfg.KeyValidatorConfig.RequiredConfigMaps(common.TigeraPrometheusNamespace)...)...)
	}

	if mc.cfg.UsePSP {
		toCreate = append(toCreate, mc.prometheusOperatorPodSecurityPolicy())
	}

	// Remove the pod monitor that existed prior to v1.25.
	var toDelete []client.Object
	toDelete = append(toDelete, &monitoringv1.PodMonitor{ObjectMeta: metav1.ObjectMeta{Name: FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}})

	return toCreate, toDelete
}

func (mc *monitorComponent) Ready() bool {
	return true
}

func (mc *monitorComponent) prometheusOperatorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoPrometheusOperator,
			Namespace: common.TigeraPrometheusNamespace,
		},
	}
}

func (mc *monitorComponent) prometheusOperatorClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"monitoring.coreos.com"},
			Resources: []string{
				"alertmanagers",
				"alertmanagers/finalizers",
				"alertmanagerconfigs",
				"prometheuses",
				"prometheuses/finalizers",
				"prometheuses/status",
				"thanosrulers",
				"thanosrulers/finalizers",
				"servicemonitors",
				"podmonitors",
				"probes",
				"prometheusrules",
			},
			Verbs: []string{"*"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"statefulsets"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{
				"configmaps",
				"secrets",
			},
			Verbs: []string{"*"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs: []string{
				"delete",
				"list",
			},
		},
		{
			APIGroups: []string{""},
			Resources: []string{
				"services",
				"services/finalizers",
				"endpoints",
			},
			Verbs: []string{
				"create",
				"delete",
				"get",
				"update",
			},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs: []string{
				"list",
				"watch",
			},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingresses"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
	}

	if mc.cfg.UsePSP {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{TigeraPrometheusPodSecurityPolicyName},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: CalicoPrometheusOperator},
		Rules:      rules,
	}
}

func (mc *monitorComponent) prometheusOperatorClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: CalicoPrometheusOperator},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      CalicoPrometheusOperator,
				Namespace: common.TigeraPrometheusNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     CalicoPrometheusOperator,
		},
	}
}

func (mc *monitorComponent) prometheusOperatorPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(TigeraPrometheusPodSecurityPolicyName)
}

func (mc *monitorComponent) alertmanager() *monitoringv1.Alertmanager {
	return &monitoringv1.Alertmanager{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.AlertmanagersKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeAlertmanager,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.AlertmanagerSpec{
			Image:              &mc.alertmanagerImage,
			ImagePullPolicy:    render.ImagePullPolicy(),
			ImagePullSecrets:   secret.GetReferenceList(mc.cfg.PullSecrets),
			NodeSelector:       mc.cfg.Installation.ControlPlaneNodeSelector,
			Replicas:           ptr.Int32ToPtr(3),
			SecurityContext:    securitycontext.NewNonRootPodContext(),
			ServiceAccountName: PrometheusServiceAccountName,
			Tolerations:        mc.cfg.Installation.ControlPlaneTolerations,
			Version:            components.ComponentCoreOSAlertmanager.Version,
		},
	}
}

func (mc *monitorComponent) alertmanagerService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeAlertmanager,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Port:       AlertmanagerPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString("web"),
				},
			},
			Selector: map[string]string{
				"alertmanager": CalicoNodeAlertmanager,
			},
		},
	}
}

func (mc *monitorComponent) prometheus() *monitoringv1.Prometheus {
	var initContainers []corev1.Container
	if mc.cfg.ServerTLSSecret.UseCertificateManagement() {
		initContainers = append(initContainers, mc.cfg.ServerTLSSecret.InitContainer(common.TigeraPrometheusNamespace))
	}
	if mc.cfg.ClientTLSSecret.UseCertificateManagement() {
		initContainers = append(initContainers, mc.cfg.ClientTLSSecret.InitContainer(common.TigeraPrometheusNamespace))
	}
	env := []corev1.EnvVar{
		{
			Name:  "PROMETHEUS_ENDPOINT_URL",
			Value: "http://localhost:9090",
		},
		{
			Name:  "LISTEN_ADDR",
			Value: fmt.Sprintf(":%d", PrometheusProxyPort),
		},
		{
			Name:  "TLS_KEY",
			Value: mc.cfg.ServerTLSSecret.VolumeMountKeyFilePath(),
		},
		{
			Name:  "TLS_CERT",
			Value: mc.cfg.ServerTLSSecret.VolumeMountCertificateFilePath(),
		},
		{
			// No other way to annotate this pod.
			Name:  "TLS_SERVER_SECRET_HASH_ANNOTATION",
			Value: mc.cfg.ServerTLSSecret.HashAnnotationValue(),
		},
		{
			// No other way to annotate this pod.
			Name:  "TLS_CLIENT_SECRET_HASH_ANNOTATION",
			Value: mc.cfg.ClientTLSSecret.HashAnnotationValue(),
		},
		{
			// No other way to annotate this pod.
			Name:  "TLS_CA_BUNDLE_HASH_ANNOTATION",
			Value: rmeta.AnnotationHash(mc.cfg.TrustedCertBundle.HashAnnotations()),
		},
		{
			Name:  "FIPS_MODE_ENABLED",
			Value: operatorv1.IsFIPSModeEnabledString(mc.cfg.Installation.FIPSMode),
		},
	}

	volumes := []corev1.Volume{
		mc.cfg.ServerTLSSecret.Volume(),
		mc.cfg.ClientTLSSecret.Volume(),
		mc.cfg.TrustedCertBundle.Volume(),
	}
	volumeMounts := append(
		mc.cfg.TrustedCertBundle.VolumeMounts(mc.SupportedOSType()),
		mc.cfg.ServerTLSSecret.VolumeMount(mc.SupportedOSType()),
		mc.cfg.ClientTLSSecret.VolumeMount(mc.SupportedOSType()),
	)

	if mc.cfg.KeyValidatorConfig != nil {
		env = append(env, mc.cfg.KeyValidatorConfig.RequiredEnv("")...)
	}

	return &monitoringv1.Prometheus{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.PrometheusesKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodePrometheus,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.PrometheusSpec{
			CommonPrometheusFields: monitoringv1.CommonPrometheusFields{
				Containers: []corev1.Container{
					{
						Name:            "authn-proxy",
						Image:           mc.prometheusServiceImage,
						ImagePullPolicy: render.ImagePullPolicy(),
						Ports: []corev1.ContainerPort{
							{
								ContainerPort: PrometheusProxyPort,
							},
						},
						Env:          env,
						VolumeMounts: volumeMounts,
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   tigeraPrometheusServiceHealthEndpoint,
									Port:   intstr.FromInt(PrometheusProxyPort),
									Scheme: "HTTPS",
								},
							},
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   tigeraPrometheusServiceHealthEndpoint,
									Port:   intstr.FromInt(PrometheusProxyPort),
									Scheme: "HTTPS",
								},
							},
						},
					},
				},
				Image:            &mc.prometheusImage,
				ImagePullPolicy:  render.ImagePullPolicy(),
				ImagePullSecrets: secret.GetReferenceList(mc.cfg.PullSecrets),
				InitContainers:   initContainers,
				// ListenLocal makes the Prometheus server listen on loopback, so that it
				// does not bind against the Pod IP. This forces traffic to go through the authn-proxy.
				ListenLocal:            true,
				NodeSelector:           mc.cfg.Installation.ControlPlaneNodeSelector,
				PodMonitorSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"team": "network-operators"}},
				Resources:              corev1.ResourceRequirements{Requests: corev1.ResourceList{"memory": resource.MustParse("400Mi")}},
				SecurityContext:        securitycontext.NewNonRootPodContext(),
				ServiceAccountName:     PrometheusServiceAccountName,
				ServiceMonitorSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "network-operators"}},
				Tolerations:            mc.cfg.Installation.ControlPlaneTolerations,
				Version:                components.ComponentCoreOSPrometheus.Version,
				VolumeMounts:           volumeMounts,
				Volumes:                volumes,
			},
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
			Retention: "24h",
			RuleSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"prometheus": CalicoNodePrometheus,
				"role":       "tigera-prometheus-rules",
			}},
		},
	}
}

func (mc *monitorComponent) prometheusServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusServiceAccountName,
			Namespace: common.TigeraPrometheusNamespace,
		},
	}
}

func (mc *monitorComponent) prometheusClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{
				"endpoints",
				"nodes",
				"pods",
				"services",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"services/proxy"},
			ResourceNames: []string{"https:tigera-api:8080"},
			Verbs:         []string{"get"},
		},
		{
			NonResourceURLs: []string{"/metrics"},
			Verbs:           []string{"get"},
		},
	}

	if mc.cfg.UsePSP {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{TigeraPrometheusPodSecurityPolicyName},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PrometheusClusterRoleName},
		Rules:      rules,
	}
}

func (mc *monitorComponent) prometheusClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PrometheusClusterRoleName},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PrometheusServiceAccountName,
				Namespace: common.TigeraPrometheusNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     PrometheusClusterRoleName,
		},
	}
}

func (mc *monitorComponent) prometheusServiceClusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: TigeraPrometheusObjectName,
		},
		Rules: rules,
	}
}

func (mc *monitorComponent) prometheusServiceClusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: TigeraPrometheusObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     TigeraPrometheusObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PrometheusServiceAccountName,
				Namespace: common.TigeraPrometheusNamespace,
			},
		},
	}
}

// prometheusServiceService sets up a service to open http connection for the prometheus instance
func (mc *monitorComponent) prometheusServiceService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusServiceServiceName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Port:       PrometheusDefaultPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(PrometheusProxyPort),
				},
			},
			Selector: map[string]string{
				"prometheus": calicoNodePrometheusServiceName,
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
					Scheme:        "https",
					TLSConfig:     mc.tlsConfig(render.CalicoNodeMetricsService),
				},
				{
					HonorLabels:   true,
					Interval:      "5s",
					Port:          "calico-bgp-metrics-port",
					ScrapeTimeout: "5s",
					Scheme:        "https",
					TLSConfig:     mc.tlsConfig(render.CalicoNodeMetricsService),
				},
			},
		},
	}
}

func (mc *monitorComponent) tlsConfig(serverName string) *monitoringv1.TLSConfig {
	return &monitoringv1.TLSConfig{
		KeyFile:  mc.cfg.ClientTLSSecret.VolumeMountKeyFilePath(),
		CertFile: mc.cfg.ClientTLSSecret.VolumeMountCertificateFilePath(),
		CAFile:   mc.cfg.TrustedCertBundle.MountPath(),
		SafeTLSConfig: monitoringv1.SafeTLSConfig{
			ServerName: serverName,
		},
	}
}

func (mc *monitorComponent) serviceMonitorElasticsearch() *monitoringv1.ServiceMonitor {
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
					Scheme:        "https",
					TLSConfig:     mc.tlsConfig(esmetrics.ElasticsearchMetricsName),
				},
			},
		},
	}
}

// serviceMonitorFluentd creates a service monitor to make Prometheus watch Fluentd. Previously, a pod monitor was used.
// However, the pod monitor does not have all the tls configuration options that we need, namely reading them from the
// file system, as opposed to getting them from watching kubernetes secrets.
func (mc *monitorComponent) serviceMonitorFluentd() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.FluentdMetricsService,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "fluentd-node"}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{render.LogCollectorNamespace}},
			Endpoints: []monitoringv1.Endpoint{
				{
					HonorLabels:   true,
					Interval:      "5s",
					Port:          render.FluentdMetricsPortName,
					ScrapeTimeout: "5s",
					Scheme:        "https",
					TLSConfig:     mc.tlsConfig(render.FluentdPrometheusTLSSecretName),
				},
			},
		},
	}
}

func (mc *monitorComponent) serviceMonitorQueryServer() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.QueryserverServiceName,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": render.QueryserverServiceName}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{render.QueryserverNamespace}},
			Endpoints: []monitoringv1.Endpoint{
				{
					HonorLabels:     true,
					Interval:        "5s",
					Port:            "queryserver",
					ScrapeTimeout:   "5s",
					Scheme:          "https",
					BearerTokenFile: bearerTokenFile,
					TLSConfig: &monitoringv1.TLSConfig{
						CAFile: mc.cfg.TrustedCertBundle.MountPath(),
						SafeTLSConfig: monitoringv1.SafeTLSConfig{
							ServerName: render.ProjectCalicoAPIServerServiceName(mc.cfg.Installation.Variant),
						},
					},
				},
			},
		},
	}
}

func (mc *monitorComponent) operatorRole() *rbacv1.Role {
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

func (mc *monitorComponent) operatorRoleBinding() *rbacv1.RoleBinding {
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
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}

// Creates a network policy to allow traffic to Alertmanager (TCP port 9093).
func allowTigeraAlertManagerPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		// Allows all egress traffic from AlertManager.
		Action:   v3.Allow,
		Protocol: &networkpolicy.TCPProtocol,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      AlertManagerPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: alertManagerSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(AlertmanagerPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic between Alertmanagers for HA configuration (TCP port 6783).
func allowTigeraAlertManagerMeshPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(9094),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.UDPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(9094),
			},
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Openshift)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      MeshAlertManagerPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: alertManagerSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Selector: alertManagerSelector,
						Ports:    networkpolicy.Ports(9094),
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.UDPProtocol,
					Destination: v3.EntityRule{
						Selector: alertManagerSelector,
						Ports:    networkpolicy.Ports(9094),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic to access the Prometheus (TCP port 9095).
func allowTigeraPrometheusPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Openshift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for Felix metrics
				Ports: networkpolicy.Ports(9081, 9091),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for BGP metrics
				Ports: networkpolicy.Ports(9900),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access form QueryServer metrics
				Ports: networkpolicy.Ports(8080),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for Kube controller port metrics.
				Ports: networkpolicy.Ports(uint16(cfg.KubeControllerPort)),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(AlertmanagerPort),
			},
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.PrometheusSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(PrometheusProxyPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic to access through tigera-prometheus-api
func allowTigeraPrometheusAPIPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.PrometheusEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusAPIPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector("tigera-prometheus-api"),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(PrometheusProxyPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow the prometheus-operatorto access the kube-apiserver
func allowTigeraPrometheusOperatorPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusOperatorPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: "operator == 'prometheus'",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

func (mc *monitorComponent) serviceMonitorCalicoKubeControllers() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeControllerMetrics,
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-kube-controllers"}},
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{"calico-system"}},
			Endpoints: []monitoringv1.Endpoint{
				{
					HonorLabels:   true,
					Interval:      "5s",
					Port:          "metrics-port",
					ScrapeTimeout: "5s",
					Scheme:        "https",
					TLSConfig:     mc.tlsConfig(KubeControllerMetrics),
				},
			},
		},
	}
}
