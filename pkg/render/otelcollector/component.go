// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package otelcollector

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	OTelCollectorName                = "otel-collector"
	OTelCollectorNamespace           = common.CalicoNamespace
	OTelCollectorServiceAccountName  = OTelCollectorName
	OTelCollectorStatefulSetName     = OTelCollectorName
	OTelCollectorServiceName         = OTelCollectorName
	OTelCollectorConfigMapName       = OTelCollectorName
	OTelCollectorContainerName       = "otel-collector"
	OTelCollectorPolicyName          = networkpolicy.CalicoComponentPolicyPrefix + OTelCollectorName
	OTelCollectorClusterRoleName     = OTelCollectorName
	OTelCollectorServerTLSSecretName = "otel-collector-tls"

	OTLPGRPCPort        = 4317
	OTLPHTTPPort        = 4318
	HealthCheckPort     = 13133
	InternalMetricsPort = 8888

	DefaultMemoryLimit         = "512Mi"
	DefaultMemoryRequest       = "128Mi"
	DefaultMemoryLimitMiB      = 409 // 80% of 512Mi
	DefaultMemorySpikeLimitMiB = 100 // ~25% of limit_mib
)

type Configuration struct {
	PullSecrets   []*corev1.Secret
	OpenShift     bool
	Installation  *operatorv1.InstallationSpec
	OTelCollector *operatorv1.OTelCollectorSpec
	// ReceiverTLSSecret is the server keypair for the OTLP receiver (mTLS termination).
	ReceiverTLSSecret certificatemanagement.KeyPairInterface
	TrustedCertBundle certificatemanagement.TrustedBundleRO
}

type component struct {
	cfg   *Configuration
	image string
}

func OTelCollector(cfg *Configuration) render.Component {
	return &component{cfg: cfg}
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error
	c.image, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	return err
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	statefulSet := c.statefulSet()
	if c.cfg.OTelCollector.OTelCollectorStatefulSet != nil {
		rcomp.ApplyStatefulSetOverrides(statefulSet, c.cfg.OTelCollector.OTelCollectorStatefulSet)
	}

	objs := []client.Object{
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.configMap(),
		c.service(),
		statefulSet,
		c.networkPolicy(),
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(OTelCollectorNamespace, c.cfg.PullSecrets...)...)...)

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}

func (c *component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: OTelCollectorServiceAccountName, Namespace: OTelCollectorNamespace},
	}
}

func (c *component) clusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: OTelCollectorClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			// Authorizes the collector's federate scrapes at the
			// tigera-prometheus authn-proxy (TokenReview +
			// SubjectAccessReview on this resource) — the same rule the
			// manager and guardian use to query Prometheus.
			{
				APIGroups:     []string{""},
				Resources:     []string{"services/proxy"},
				ResourceNames: []string{"calico-node-prometheus:9090"},
				Verbs:         []string{"get"},
			},
		},
	}
}

func (c *component) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: OTelCollectorClusterRoleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     OTelCollectorClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      OTelCollectorServiceAccountName,
				Namespace: OTelCollectorNamespace,
			},
		},
	}
}

func (c *component) configMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: OTelCollectorConfigMapName, Namespace: OTelCollectorNamespace},
		Data: map[string]string{
			"config.yaml": c.collectorConfig(),
		},
	}
}

func (c *component) metricsEnabled() bool {
	return c.cfg.OTelCollector.Metrics != nil &&
		c.cfg.OTelCollector.Metrics.Enabled != nil &&
		*c.cfg.OTelCollector.Metrics.Enabled == operatorv1.OTelMetricsEnable
}

func (c *component) hasLogs() bool {
	return c.cfg.OTelCollector.Logs != nil && len(c.cfg.OTelCollector.Logs.Types) > 0
}

type configTemplateData struct {
	HasLogs          bool
	ReceiverTLS      bool
	ReceiverCertFile string
	ReceiverKeyFile  string
	ReceiverClientCA string
	MetricsEnabled   bool
	MetricsCAFile    string
	// PrometheusFederateTarget is the host:port of the tigera-prometheus
	// authn-proxy fronting the /federate endpoint.
	PrometheusFederateTarget string
	Exporters                []exporterEntry
	ExporterNames            string
	HealthCheckPort          int
	InternalMetricsPort      int
	MemoryLimitMiB           int
	MemorySpikeLimitMiB      int
}

type exporterEntry struct {
	Prefix      string
	Name        string
	Endpoint    string
	TLSInsecure bool
}

var collectorConfigTmpl = template.Must(template.New("config").Parse(`receivers:
{{- if .HasLogs}}
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
{{- if .ReceiverTLS}}
        tls:
          cert_file: {{.ReceiverCertFile}}
          key_file: {{.ReceiverKeyFile}}
          client_ca_file: {{.ReceiverClientCA}}
{{- end}}
{{- end}}
{{- if .MetricsEnabled}}
  # Federate everything the in-cluster tigera-prometheus already scrapes
  # (calico-node, typha/kube-controllers, calico-api, fluent-bit,
  # elasticsearch, operator — every ServiceMonitor, including future ones)
  # instead of re-implementing per-component scrape configs and their TLS
  # quirks here. The request goes through Prometheus's authn-proxy: bearer
  # token is the pod's ServiceAccount token, authorized by the
  # services/proxy RBAC rule on the collector's ClusterRole.
  prometheus:
    config:
      scrape_configs:
        - job_name: 'tigera-prometheus-federate'
          scheme: https
          metrics_path: /federate
          params:
            'match[]': ['{__name__=~".+"}']
          # Keep the original job/instance labels from the federated series.
          honor_labels: true
          authorization:
            credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
          tls_config:
            ca_file: {{.MetricsCAFile}}
          static_configs:
            - targets: ['{{.PrometheusFederateTarget}}']
{{- end}}

exporters:
{{- range .Exporters}}
  {{.Prefix}}/{{.Name}}:
    endpoint: {{.Endpoint}}
{{- if .TLSInsecure}}
    tls:
      insecure: true
{{- end}}
{{- end}}

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: {{.MemoryLimitMiB}}
    spike_limit_mib: {{.MemorySpikeLimitMiB}}
{{- if .HasLogs}}
  transform/service_name:
    log_statements:
      - context: log
        statements:
          - set(resource.attributes["service.name"], "audit") where IsMap(body) and body["auditID"] != nil
          - set(resource.attributes["service.name"], "dns") where IsMap(body) and body["qname"] != nil
          - set(resource.attributes["service.name"], "flows") where IsMap(body) and body["bytes_in"] != nil
          - set(resource.attributes["service.name"], "unknown") where resource.attributes["service.name"] == nil or resource.attributes["service.name"] == "unknown_service"
{{- end}}

extensions:
  health_check:
    endpoint: 0.0.0.0:{{.HealthCheckPort}}

service:
  telemetry:
    metrics:
      readers:
        - pull:
            exporter:
              prometheus:
                host: "0.0.0.0"
                port: {{.InternalMetricsPort}}
  extensions: [health_check]
  pipelines:
{{- if .HasLogs}}
    logs:
      receivers: [otlp]
      processors: [memory_limiter, transform/service_name]
      exporters: [{{.ExporterNames}}]
{{- end}}
{{- if .MetricsEnabled}}
    metrics:
      receivers: [prometheus]
      processors: [memory_limiter]
      exporters: [{{.ExporterNames}}]
{{- end}}
`))

func (c *component) collectorConfig() string {
	var exporters []exporterEntry
	var exporterNames []string
	for _, exp := range c.cfg.OTelCollector.Exporters {
		var prefix string
		if exp.Protocol == operatorv1.OTelProtocolHTTP {
			prefix = "otlphttp"
		} else {
			prefix = "otlp"
		}
		exporters = append(exporters, exporterEntry{
			Prefix:      prefix,
			Name:        exp.Name,
			Endpoint:    exp.Endpoint,
			TLSInsecure: exp.TLSInsecure != nil && *exp.TLSInsecure,
		})
		exporterNames = append(exporterNames, fmt.Sprintf("%s/%s", prefix, exp.Name))
	}

	data := configTemplateData{
		HasLogs:             c.hasLogs(),
		MetricsEnabled:      c.metricsEnabled(),
		Exporters:           exporters,
		ExporterNames:       strings.Join(exporterNames, ", "),
		HealthCheckPort:     HealthCheckPort,
		InternalMetricsPort: InternalMetricsPort,
		MemoryLimitMiB:      DefaultMemoryLimitMiB,
		MemorySpikeLimitMiB: DefaultMemorySpikeLimitMiB,
	}

	if c.hasLogs() && c.cfg.ReceiverTLSSecret != nil && c.cfg.TrustedCertBundle != nil {
		data.ReceiverTLS = true
		data.ReceiverCertFile = c.cfg.ReceiverTLSSecret.VolumeMountCertificateFilePath()
		data.ReceiverKeyFile = c.cfg.ReceiverTLSSecret.VolumeMountKeyFilePath()
		data.ReceiverClientCA = c.cfg.TrustedCertBundle.MountPath()
	}

	if c.metricsEnabled() && c.cfg.TrustedCertBundle != nil {
		data.MetricsCAFile = c.cfg.TrustedCertBundle.MountPath()
		data.PrometheusFederateTarget = fmt.Sprintf("%s.%s.svc:%d",
			monitor.PrometheusServiceServiceName, common.TigeraPrometheusNamespace, monitor.PrometheusDefaultPort)
	}

	var buf bytes.Buffer
	if err := collectorConfigTmpl.Execute(&buf, data); err != nil {
		panic(fmt.Sprintf("failed to render otel collector config: %v", err))
	}
	return buf.String()
}

func (c *component) service() *corev1.Service {
	ports := []corev1.ServicePort{
		{
			Name:       "otlp-http",
			Port:       OTLPHTTPPort,
			TargetPort: intstr.FromInt32(OTLPHTTPPort),
			Protocol:   corev1.ProtocolTCP,
		},
		{
			Name:       "metrics",
			Port:       InternalMetricsPort,
			TargetPort: intstr.FromInt32(InternalMetricsPort),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OTelCollectorServiceName,
			Namespace: OTelCollectorNamespace,
			Labels:    map[string]string{"k8s-app": OTelCollectorStatefulSetName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": OTelCollectorStatefulSetName},
			Ports:    ports,
		},
	}
}

func (c *component) container() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "config",
			MountPath: "/etc/otel",
			ReadOnly:  true,
		},
	}

	if c.cfg.TrustedCertBundle != nil {
		volumeMounts = append(volumeMounts,
			c.cfg.TrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux)...,
		)
	}

	if c.cfg.ReceiverTLSSecret != nil {
		volumeMounts = append(volumeMounts,
			c.cfg.ReceiverTLSSecret.VolumeMount(rmeta.OSTypeLinux),
		)
	}

	return corev1.Container{
		Name:    OTelCollectorContainerName,
		Image:   c.image,
		Command: []string{"/usr/bin/otelcol", "--config=/etc/otel/config.yaml"},
		Ports: []corev1.ContainerPort{
			// No otlp-grpc port: the receiver is HTTP-only (fluent-bit's
			// opentelemetry output has no gRPC mode). 4317 appears only in
			// the egress policy for outbound gRPC exporters.
			{Name: "otlp-http", ContainerPort: OTLPHTTPPort, Protocol: corev1.ProtocolTCP},
			{Name: "health", ContainerPort: HealthCheckPort, Protocol: corev1.ProtocolTCP},
			{Name: "metrics", ContainerPort: InternalMetricsPort, Protocol: corev1.ProtocolTCP},
		},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(DefaultMemoryLimit),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(DefaultMemoryRequest),
			},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.FromInt32(HealthCheckPort),
				},
			},
			PeriodSeconds: 10,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.FromInt32(HealthCheckPort),
				},
			},
			PeriodSeconds: 10,
		},
		VolumeMounts: volumeMounts,
	}
}

func (c *component) statefulSet() *appsv1.StatefulSet {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: OTelCollectorConfigMapName},
				},
			},
		},
	}

	if c.cfg.TrustedCertBundle != nil {
		volumes = append(volumes, c.cfg.TrustedCertBundle.Volume())
	}

	if c.cfg.ReceiverTLSSecret != nil {
		volumes = append(volumes, c.cfg.ReceiverTLSSecret.Volume())
	}

	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OTelCollectorStatefulSetName,
			Namespace: OTelCollectorNamespace,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    c.cfg.Installation.ControlPlaneReplicas,
			ServiceName: OTelCollectorServiceName,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": OTelCollectorStatefulSetName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   OTelCollectorStatefulSetName,
					Labels: map[string]string{"k8s-app": OTelCollectorStatefulSetName},
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: OTelCollectorServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         []corev1.Container{c.container()},
					Volumes:            volumes,
				},
			},
		},
	}
}

func (c *component) networkPolicy() *v3.NetworkPolicy {
	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(OTLPHTTPPort),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(InternalMetricsPort),
			},
		},
	}

	egressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(OTLPGRPCPort, OTLPHTTPPort),
			},
		},
	}

	for _, exp := range c.cfg.OTelCollector.Exporters {
		if u, err := url.Parse(exp.Endpoint); err == nil {
			portStr := u.Port()
			if portStr == "" {
				if u.Scheme == "https" {
					portStr = "443"
				} else {
					portStr = "80"
				}
			}
			if p, err := strconv.Atoi(portStr); err == nil {
				egressRules = append(egressRules, v3.Rule{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(uint16(p)),
					},
				})
			}
		}
	}

	if c.metricsEnabled() {
		// Federation scrapes go to the tigera-prometheus authn-proxy only.
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.PrometheusEntityRule,
		})
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: OTelCollectorPolicyName, Namespace: OTelCollectorNamespace},
		Spec: v3.NetworkPolicySpec{
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(OTelCollectorStatefulSetName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}
