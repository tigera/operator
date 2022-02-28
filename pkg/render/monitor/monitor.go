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

	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
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
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
)

const (
	MonitoringAPIVersion        = "monitoring.coreos.com/v1"
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
	PrometheusClientTLSSecretName   = "calico-node-prometheus-client-tls"
	calicoNodePrometheusServiceName = "calico-node-prometheus"

	tigeraPrometheusServiceHealthEndpoint = "/health"

	AlertmanagerConfigSecret = "alertmanager-calico-node-alertmanager"

	prometheusServiceAccountName = "prometheus"
)

func Monitor(cfg *Config) render.Component {
	var tlsSecrets []*corev1.Secret
	var tlsHash string
	var clientTLSHash string
	if cfg.Installation.CertificateManagement == nil {
		tlsSecrets = []*corev1.Secret{
			secret.CopyToNamespace(common.TigeraPrometheusNamespace, cfg.ServerTLSSecret)[0],
			secret.CopyToNamespace(common.TigeraPrometheusNamespace, cfg.ClientTLSSecret)[0],
		}
		tlsHash = rmeta.AnnotationHash(cfg.ServerTLSSecret.Data)
		clientTLSHash = rmeta.AnnotationHash(cfg.ClientTLSSecret.Data)
	}

	return &monitorComponent{
		cfg:           cfg,
		tlsSecrets:    tlsSecrets,
		tlsHash:       tlsHash,
		clientTLSHash: clientTLSHash,
	}
}

// Config contains all the config information needed to render the Monitor component.
type Config struct {
	Installation             *operatorv1.InstallationSpec
	PullSecrets              []*corev1.Secret
	AlertmanagerConfigSecret *corev1.Secret
	KeyValidatorConfig       authentication.KeyValidatorConfig
	ServerTLSSecret          *corev1.Secret
	ClientTLSSecret          *corev1.Secret
	ClusterDomain            string
	TrustedCertBundle        *corev1.ConfigMap
}

type monitorComponent struct {
	cfg                    *Config
	alertmanagerImage      string
	prometheusImage        string
	prometheusServiceImage string
	csrImage               string
	tlsSecrets             []*corev1.Secret
	tlsHash                string
	clientTLSHash          string
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

	if mc.cfg.Installation.CertificateManagement != nil {
		mc.csrImage, err = render.ResolveCSRInitImage(mc.cfg.Installation, is)
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
		render.CreateNamespace(common.TigeraPrometheusNamespace, mc.cfg.Installation.KubernetesProvider),
		mc.cfg.TrustedCertBundle,
	}

	// Create role and role bindings first.
	// Operator needs the create/update roles for Alertmanger configuration secret for example.
	toCreate = append(toCreate,
		mc.role(),
		mc.roleBinding(),
	)

	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(common.TigeraPrometheusNamespace, mc.cfg.PullSecrets...)...)...)
	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(common.TigeraPrometheusNamespace, mc.cfg.AlertmanagerConfigSecret)...)...)

	// This is to delete a service that had been released in v3.8 with a typo in the name.
	// TODO Remove the toDelete object after we drop support for v3.8.
	toDelete := []client.Object{
		mc.serviceMonitorElasicsearchToDelete(),
	}
	if mc.cfg.Installation.CertificateManagement == nil {
		toCreate = append(toCreate, secret.ToRuntimeObjects(mc.tlsSecrets...)...)
		toDelete = append(toDelete, render.CSRClusterRoleBinding(prometheusServiceAccountName, common.TigeraPrometheusNamespace))
	} else {
		toDelete = append(toDelete, secret.ToRuntimeObjects(mc.tlsSecrets...)...)
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
		mc.serviceMonitorFluentd(),
		mc.prometheusHTTPAPIService(),
		mc.clusterRole(),
		mc.clusterRoleBinding(),
	)

	if mc.cfg.KeyValidatorConfig != nil {
		toCreate = append(toCreate, secret.ToRuntimeObjects(mc.cfg.KeyValidatorConfig.RequiredSecrets(common.TigeraPrometheusNamespace)...)...)
		toCreate = append(toCreate, configmap.ToRuntimeObjects(mc.cfg.KeyValidatorConfig.RequiredConfigMaps(common.TigeraPrometheusNamespace)...)...)
	}

	// Remove the pod monitor that existed prior to v3.12.
	toDelete = append(toDelete, &monitoringv1.PodMonitor{ObjectMeta: metav1.ObjectMeta{Name: FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}})

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
			ImagePullSecrets: secret.GetReferenceList(mc.cfg.PullSecrets),
			Replicas:         ptr.Int32ToPtr(3),
			Version:          components.ComponentCoreOSAlertmanager.Version,
			Tolerations:      mc.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:     mc.cfg.Installation.ControlPlaneNodeSelector,
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
	var initContainers []corev1.Container
	if mc.cfg.Installation.CertificateManagement != nil {
		svcDNSNames := dns.GetServiceDNSNames(PrometheusHTTPAPIServiceName, common.TigeraPrometheusNamespace, mc.cfg.ClusterDomain)
		clientInit := render.CreateCSRInitContainer(
			mc.cfg.Installation.CertificateManagement,
			mc.csrImage,
			PrometheusClientTLSSecretName,
			PrometheusHTTPAPIServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			[]string{PrometheusClientTLSSecretName},
			common.TigeraPrometheusNamespace)
		// Make sure the names are not identical for the two init containers.
		clientInit.Name = fmt.Sprintf("%s-%s", PrometheusClientTLSSecretName, clientInit.Name)
		initContainers = append(initContainers, render.CreateCSRInitContainer(
			mc.cfg.Installation.CertificateManagement,
			mc.csrImage,
			PrometheusTLSSecretName,
			PrometheusHTTPAPIServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			svcDNSNames,
			common.TigeraPrometheusNamespace),
			clientInit)

	}
	volumes := []corev1.Volume{
		{
			Name:         PrometheusTLSSecretName,
			VolumeSource: render.CertificateVolumeSource(mc.cfg.Installation.CertificateManagement, PrometheusTLSSecretName),
		},
		{
			Name:         PrometheusClientTLSSecretName,
			VolumeSource: render.CertificateVolumeSource(mc.cfg.Installation.CertificateManagement, PrometheusClientTLSSecretName),
		},
		{
			Name: mc.cfg.TrustedCertBundle.Name,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: mc.cfg.TrustedCertBundle.Name},
				},
			},
		},
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
			Name:  "TLS_SERVER_SECRET_HASH_ANNOTATION",
			Value: mc.tlsHash,
		},
		{
			// No other way to annotate this pod.
			Name:  "TLS_CLIENT_SECRET_HASH_ANNOTATION",
			Value: mc.clientTLSHash,
		},
		{
			// No other way to annotate this pod.
			Name:  "TLS_CA_BUNDLE_HASH_ANNOTATION",
			Value: rmeta.AnnotationHash(mc.cfg.TrustedCertBundle.Data),
		},
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      PrometheusTLSSecretName,
			MountPath: "/tls",
			ReadOnly:  true,
		},
		{
			Name:      PrometheusClientTLSSecretName,
			MountPath: "/client-tls",
			ReadOnly:  true,
		},
		{
			Name:      mc.cfg.TrustedCertBundle.Name,
			MountPath: fmt.Sprintf("/%s", mc.cfg.TrustedCertBundle.Name),
			ReadOnly:  true,
		},
	}

	if mc.cfg.KeyValidatorConfig != nil {
		volumeMounts = append(volumeMounts, mc.cfg.KeyValidatorConfig.RequiredVolumeMounts()...)
		env = append(env, mc.cfg.KeyValidatorConfig.RequiredEnv("")...)
		volumes = append(volumes, mc.cfg.KeyValidatorConfig.RequiredVolumes()...)
	}

	return &monitoringv1.Prometheus{
		TypeMeta: metav1.TypeMeta{Kind: monitoringv1.PrometheusesKind, APIVersion: MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodePrometheus,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: monitoringv1.PrometheusSpec{
			Image:              &mc.prometheusImage,
			ImagePullSecrets:   secret.GetReferenceList(mc.cfg.PullSecrets),
			ServiceAccountName: prometheusServiceAccountName,
			Volumes:            volumes,
			VolumeMounts:       volumeMounts,
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
			Version:                components.ComponentCoreOSPrometheus.Version,
			Retention:              "24h",
			Resources:              corev1.ResourceRequirements{Requests: corev1.ResourceList{"memory": resource.MustParse("400Mi")}},
			RuleSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"prometheus": CalicoNodePrometheus,
				"role":       "tigera-prometheus-rules",
			}},
			Tolerations:  mc.cfg.Installation.ControlPlaneTolerations,
			NodeSelector: mc.cfg.Installation.ControlPlaneNodeSelector,
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
		KeyFile:  fmt.Sprintf("/client-tls/%s", corev1.TLSPrivateKeyKey),
		CertFile: fmt.Sprintf("/client-tls/%s", corev1.TLSCertKey),
		CAFile:   fmt.Sprintf("/%s/%s", mc.cfg.TrustedCertBundle.Name, corev1.ServiceAccountRootCAKey),
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
					Port:          render.FluentdMetricsPort,
					ScrapeTimeout: "5s",
					Scheme:        "https",
					TLSConfig:     mc.tlsConfig(render.FluentdPrometheusTLSSecretName),
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
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}
