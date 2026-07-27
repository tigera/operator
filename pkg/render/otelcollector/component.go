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
	_ "embed"
	"fmt"
	"net"
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
	exporterPrefixHTTP  = "otlphttp"
	exporterPrefixGRPC  = "otlp_grpc"
	HealthCheckPort     = 13133
	InternalMetricsPort = 8888

	DefaultMemoryLimit         = "512Mi"
	DefaultMemoryRequest       = "128Mi"
	DefaultMemoryLimitMiB      = 409  // 80% of 512Mi
	DefaultMemorySpikeLimitMiB = 100  // ~25% of limit_mib
	DefaultBatchMaxSize        = 2000 // keep each export under gRPC's 4MB default

	configHashAnnotation = "hash.operator.tigera.io/otel-collector-config"
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
	cfg          *Configuration
	image        string
	renderedConf string
}

func OTelCollector(cfg *Configuration) (render.Component, error) {
	c := &component{cfg: cfg}
	conf, err := c.collectorConfig()
	if err != nil {
		return nil, err
	}
	c.renderedConf = conf
	return c, nil
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
			"config.yaml": c.renderedConf,
		},
	}
}

func (c *component) metricsEnabled() bool {
	return c.cfg.OTelCollector.MetricsEnabled()
}

func (c *component) hasLogs() bool {
	return c.cfg.OTelCollector.HasLogs()
}

func (c *component) receiverTLSReady() bool {
	return c.hasLogs() && c.cfg.ReceiverTLSSecret != nil && c.cfg.TrustedCertBundle != nil
}

func (c *component) metricsTLSReady() bool {
	return c.metricsEnabled() && c.cfg.TrustedCertBundle != nil
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
	BatchMaxSize             int
}

type exporterEntry struct {
	Prefix      string
	Name        string
	Endpoint    string
	TLSInsecure bool
}

//go:embed collector-config.yaml.template
var collectorConfigStr string

var collectorConfigTmpl = template.Must(template.New("config").Parse(collectorConfigStr))

func (c *component) collectorConfig() (string, error) {
	var exporters []exporterEntry
	var exporterNames []string
	for _, exp := range c.cfg.OTelCollector.Exporters {
		var prefix string
		if exp.Protocol == operatorv1.OTelProtocolHTTP {
			prefix = exporterPrefixHTTP
		} else {
			prefix = exporterPrefixGRPC
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
		BatchMaxSize:        DefaultBatchMaxSize,
	}

	if c.receiverTLSReady() {
		data.ReceiverTLS = true
		data.ReceiverCertFile = c.cfg.ReceiverTLSSecret.VolumeMountCertificateFilePath()
		data.ReceiverKeyFile = c.cfg.ReceiverTLSSecret.VolumeMountKeyFilePath()
		data.ReceiverClientCA = c.cfg.TrustedCertBundle.MountPath()
	}

	if c.metricsTLSReady() {
		data.MetricsCAFile = c.cfg.TrustedCertBundle.MountPath()
		data.PrometheusFederateTarget = fmt.Sprintf("%s.%s.svc:%d",
			monitor.PrometheusServiceServiceName, common.TigeraPrometheusNamespace, monitor.PrometheusDefaultPort)
	}

	var buf bytes.Buffer
	if err := collectorConfigTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render otel collector config: %w", err)
	}
	return buf.String(), nil
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
		ReadinessProbe:  healthProbe(),
		LivenessProbe:   healthProbe(),
		VolumeMounts:    volumeMounts,
	}
}

func healthProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/",
				Port: intstr.FromInt32(HealthCheckPort),
			},
		},
		PeriodSeconds: 10,
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
					Name:        OTelCollectorStatefulSetName,
					Labels:      map[string]string{"k8s-app": OTelCollectorStatefulSetName},
					Annotations: map[string]string{configHashAnnotation: rmeta.AnnotationHash(c.renderedConf)},
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
		if port, ok := resolvePort(exp.Endpoint); ok {
			egressRules = append(egressRules, v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Ports: networkpolicy.Ports(uint16(port)),
				},
			})
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
			Ingress: []v3.Rule{
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
			},
			Egress: egressRules,
		},
	}
}

// resolvePort extracts a TCP port from an endpoint string. Accepts bare
// host:port ("otlp.example.com:4317") or full URLs ("https://otlp.example.com:443"),
// falling back to the scheme's default port (443 for https, 80 for http).
func resolvePort(endpoint string) (int, bool) {
	if _, portStr, err := net.SplitHostPort(endpoint); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			return p, true
		}
	}
	if u, err := url.Parse(endpoint); err == nil {
		if portStr := u.Port(); portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
				return p, true
			}
		}
		switch u.Scheme {
		case "https":
			return 443, true
		case "http":
			return 80, true
		}
	}
	return 0, false
}
