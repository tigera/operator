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

package monitor

import (
	_ "embed"
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
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	MonitoringAPIVersion = "monitoring.coreos.com/v1"

	CalicoNodeAlertmanager      = "calico-node-alertmanager"
	CalicoNodeMonitor           = "calico-node-monitor"
	CalicoNodePrometheus        = "calico-node-prometheus"
	ElasticsearchMetrics        = "elasticsearch-metrics"
	FluentdMetrics              = "fluentd-metrics"
	TigeraPrometheusObjectName  = "tigera-prometheus"
	TigeraPrometheusSAName      = "prometheus"
	TigeraPrometheusDPRate      = "tigera-prometheus-dp-rate"
	TigeraPrometheusRole        = "tigera-prometheus-role"
	TigeraPrometheusRoleBinding = "tigera-prometheus-role-binding"

	PrometheusHTTPAPIServiceName    = "prometheus-http-api"
	PrometheusDefaultPort           = 9090
	PrometheusProxyPort             = 9095
	PrometheusTLSSecretName         = "calico-node-prometheus-tls"
	calicoNodePrometheusServiceName = "calico-node-prometheus"

	tigeraPrometheusServiceHealthEndpoint = "/health"

	AlertmanagerConfigSecret = "alertmanager-calico-node-alertmanager"

	prometheusServiceAccountName = "prometheus"
)

func Monitor(
	installation *operatorv1.InstallationSpec,
	pullSecrets []*corev1.Secret,
	alertmanagerConfigSecret *corev1.Secret,
	tlsSecret *corev1.Secret,
	clusterDomain string,
	keyValidatorConfig authentication.KeyValidatorConfig,
) render.Component {
	var tlsSecrets []*corev1.Secret
	var tlsHash string
	if installation.CertificateManagement == nil {
		tlsSecrets = []*corev1.Secret{secret.CopyToNamespace(common.TigeraPrometheusNamespace, tlsSecret)[0]}
		tlsHash = rmeta.AnnotationHash(tlsSecret.Data)
	}
	return &monitorComponent{
		installation:             installation,
		pullSecrets:              pullSecrets,
		alertmanagerConfigSecret: alertmanagerConfigSecret,
		tlsSecrets:               tlsSecrets,
		tlsHash:                  tlsHash,
		clusterDomain:            clusterDomain,
		keyValidatorConfig:       keyValidatorConfig,
	}
}

type monitorComponent struct {
	installation             *operatorv1.InstallationSpec
	pullSecrets              []*corev1.Secret
	alertmanagerImage        string
	prometheusImage          string
	alertmanagerConfigSecret *corev1.Secret
	prometheusServiceImage   string
	csrImage                 string
	tlsSecrets               []*corev1.Secret
	tlsHash                  string
	keyValidatorConfig       authentication.KeyValidatorConfig
	clusterDomain            string
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

	mc.prometheusServiceImage, err = components.GetReference(components.ComponentTigeraPrometheusService, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if mc.installation.CertificateManagement != nil {
		mc.csrImage, err = render.ResolveCSRInitImage(mc.installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
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
		render.CreateNamespace(common.TigeraPrometheusNamespace, mc.installation.KubernetesProvider),
	}

	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(common.TigeraPrometheusNamespace, mc.pullSecrets...)...)...)
	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(common.TigeraPrometheusNamespace, mc.alertmanagerConfigSecret)...)...)

	toCreate = append(toCreate,
		mc.role(),
		mc.roleBinding(),
	)

	if mc.installation.CertificateManagement == nil {
		toCreate = append(toCreate, secret.ToRuntimeObjects(mc.tlsSecrets...)...)
	} else {
		toCreate = append(toCreate, render.CSRClusterRoleBinding(prometheusServiceAccountName, common.TigeraPrometheusNamespace))
	}
	toCreate = append(toCreate,
		mc.alertmanagerService(),
		mc.alertmanager(),
		mc.prometheusServiceAccount(),
		mc.prometheusClusterRole(),
		mc.prometheusClusterRoleBinding(),
		mc.prometheus(),
		mc.prometheusRule(),
		mc.serviceMonitorCalicoNode(),
		mc.serviceMonitorElasticsearch(),
		mc.podMonitor(),
		mc.prometheusHTTPAPIService(),
		mc.clusterRole(),
		mc.clusterRoleBinding(),
	)

	if mc.keyValidatorConfig != nil {
		toCreate = append(toCreate, secret.ToRuntimeObjects(mc.keyValidatorConfig.RequiredSecrets(common.TigeraPrometheusNamespace)...)...)
		toCreate = append(toCreate, configmap.ToRuntimeObjects(mc.keyValidatorConfig.RequiredConfigMaps(common.TigeraPrometheusNamespace)...)...)
	}

	// This is to delete a service that had been released in v3.8 with a typo in the name.
	// TODO Remove the toDelete object after we drop support for v3.8.
	toDelete := []client.Object{
		mc.serviceMonitorElasicsearchToDelete(),
	}

	return toCreate, toDelete
}

func (mc *monitorComponent) clusterRole() client.Object {
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

func (mc *monitorComponent) clusterRoleBinding() client.Object {
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
				Name:      TigeraPrometheusSAName,
				Namespace: common.TigeraPrometheusNamespace,
			},
		},
	}
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
			Tolerations:      mc.installation.ControlPlaneTolerations,
			NodeSelector:     mc.installation.ControlPlaneNodeSelector,
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
					Port:       9093,
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
	certVolume := corev1.Volume{
		Name: PrometheusTLSSecretName,
	}

	var initContainers []corev1.Container
	if mc.installation.CertificateManagement != nil {
		svcDNSNames := dns.GetServiceDNSNames(PrometheusHTTPAPIServiceName, common.TigeraPrometheusNamespace, mc.clusterDomain)

		initContainers = append(initContainers, render.CreateCSRInitContainer(
			mc.installation.CertificateManagement,
			mc.csrImage,
			PrometheusTLSSecretName,
			PrometheusHTTPAPIServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			svcDNSNames,
			common.TigeraPrometheusNamespace))

		certVolume.VolumeSource = corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
	} else {
		certVolume.VolumeSource = corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: PrometheusTLSSecretName,
			},
		}
	}
	volumes := []corev1.Volume{
		certVolume,
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
			// No other way to annotate this pod.
			Name:  "TLS_SECRET_HASH_ANNOTATION",
			Value: mc.tlsHash,
		},
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      PrometheusTLSSecretName,
			MountPath: "/tls",
			ReadOnly:  true,
		},
	}

	if mc.keyValidatorConfig != nil {
		volumeMounts = append(volumeMounts, mc.keyValidatorConfig.RequiredVolumeMounts()...)
		env = append(env, mc.keyValidatorConfig.RequiredEnv("")...)
		volumes = append(volumes, mc.keyValidatorConfig.RequiredVolumes()...)
	}

	return &monitoringv1.Prometheus{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.PrometheusesKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodePrometheus,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.PrometheusSpec{
			Image:              &mc.prometheusImage,
			ImagePullSecrets:   secret.GetReferenceList(mc.pullSecrets),
			ServiceAccountName: prometheusServiceAccountName,
			Volumes:            volumes,
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:  "authn-proxy",
					Image: mc.prometheusServiceImage,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: PrometheusProxyPort,
						},
					},
					Env:          env,
					VolumeMounts: volumeMounts,
					ReadinessProbe: &corev1.Probe{
						Handler: corev1.Handler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   tigeraPrometheusServiceHealthEndpoint,
								Port:   intstr.FromInt(PrometheusProxyPort),
								Scheme: "HTTPS",
							},
						},
					},
					LivenessProbe: &corev1.Probe{
						Handler: corev1.Handler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   tigeraPrometheusServiceHealthEndpoint,
								Port:   intstr.FromInt(PrometheusProxyPort),
								Scheme: "HTTPS",
							},
						},
					},
				},
			},
			// ListenLocal makes the Prometheus server listen on loopback, so that it
			// does not bind against the Pod IP. This forces traffic to go through the authn-proxy.
			ListenLocal:            true,
			ServiceMonitorSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "network-operators"}},
			PodMonitorSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"team": "network-operators"}},
			Version:                components.ComponentPrometheus.Version,
			Retention:              "24h",
			Resources:              corev1.ResourceRequirements{Requests: corev1.ResourceList{"memory": resource.MustParse("400Mi")}},
			RuleSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"prometheus": CalicoNodePrometheus,
				"role":       "tigera-prometheus-rules",
			}},
			Tolerations:  mc.installation.ControlPlaneTolerations,
			NodeSelector: mc.installation.ControlPlaneNodeSelector,
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

func (mc *monitorComponent) prometheusServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      prometheusServiceAccountName,
			Namespace: common.TigeraPrometheusNamespace,
		},
	}
}

func (mc *monitorComponent) prometheusClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus",
		},
		Rules: []rbacv1.PolicyRule{
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
				NonResourceURLs: []string{"/metrics"},
				Verbs:           []string{"get"},
			},
		},
	}
}

func (mc *monitorComponent) prometheusClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      prometheusServiceAccountName,
				Namespace: common.TigeraPrometheusNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "prometheus",
		},
	}
}

// prometheusHTTPAPIService sets up a service to open http connection for the prometheus instance
func (mc *monitorComponent) prometheusHTTPAPIService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusHTTPAPIServiceName,
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
				},
			},
		},
	}
}

// This is to delete a service that had been released in v3.8 with a typo in the name.
// TODO Remove this object after we drop support for v3.8.
func (mc *monitorComponent) serviceMonitorElasicsearchToDelete() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "elasticearch-metrics",
			Namespace: common.TigeraPrometheusNamespace,
			Labels:    map[string]string{"team": "network-operators"},
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
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}
