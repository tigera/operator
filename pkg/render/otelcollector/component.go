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
	"fmt"
	"strings"

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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	OTelCollectorName               = "otel-collector"
	OTelCollectorNamespace          = common.CalicoNamespace
	OTelCollectorServiceAccountName = OTelCollectorName
	OTelCollectorStatefulSetName    = OTelCollectorName
	OTelCollectorServiceName        = OTelCollectorName
	OTelCollectorConfigMapName      = OTelCollectorName
	OTelCollectorContainerName      = "otel-collector"
	OTelCollectorPolicyName         = networkpolicy.CalicoComponentPolicyPrefix + OTelCollectorName
	OTelCollectorClusterRoleName    = OTelCollectorName

	FluentForwardPort = 8006
	OTLPGRPCPort      = 4317
	OTLPHTTPPort      = 4318
	HealthCheckPort   = 13133
)

// LogForwarderProtocol determines which receiver the collector uses for log ingestion.
type LogForwarderProtocol int

const (
	// LogForwarderFluentdHTTP uses the custom fluentdhttp receiver (Fluentd out_http → HTTP JSON).
	LogForwarderFluentdHTTP LogForwarderProtocol = iota
	// LogForwarderOTLP uses the OTLP receiver (native OTLP output).
	LogForwarderOTLP
)

type Configuration struct {
	PullSecrets          []*corev1.Secret
	OpenShift            bool
	Installation         *operatorv1.InstallationSpec
	OTelCollector        *operatorv1.OTelCollectorSpec
	LogForwarderProtocol LogForwarderProtocol
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
	c.image, err = components.GetReference(components.ComponentTigeraCalico, reg, path, prefix, is)
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
			{
				APIGroups: []string{""},
				Resources: []string{"nodes", "pods", "services", "endpoints"},
				Verbs:     []string{"get", "list", "watch"},
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

func (c *component) collectorConfig() string {
	var b strings.Builder

	// Receivers
	b.WriteString("receivers:\n")

	hasLogs := c.cfg.OTelCollector.Logs != nil && len(c.cfg.OTelCollector.Logs.Types) > 0
	if hasLogs {
		switch c.cfg.LogForwarderProtocol {
		case LogForwarderOTLP:
			b.WriteString(fmt.Sprintf("  otlp:\n    protocols:\n      http:\n        endpoint: 0.0.0.0:%d\n", OTLPHTTPPort))
		default:
			b.WriteString(fmt.Sprintf("  fluentdhttp:\n    endpoint: 0.0.0.0:%d\n", FluentForwardPort))
		}
	}

	metricsEnabled := c.cfg.OTelCollector.Metrics != nil &&
		c.cfg.OTelCollector.Metrics.Enabled != nil &&
		*c.cfg.OTelCollector.Metrics.Enabled == operatorv1.OTelMetricsEnable
	if metricsEnabled {
		b.WriteString("  prometheus:\n    config:\n      scrape_configs:\n")
		b.WriteString("        - job_name: 'calico-metrics'\n")
		b.WriteString("          kubernetes_sd_configs:\n")
		b.WriteString("            - role: endpoints\n")
	}

	// Exporters
	b.WriteString("\nexporters:\n")
	for _, exp := range c.cfg.OTelCollector.Exporters {
		switch exp.Protocol {
		case operatorv1.OTelProtocolHTTP:
			b.WriteString(fmt.Sprintf("  otlphttp/%s:\n    endpoint: %s\n", exp.Name, exp.Endpoint))
		default:
			b.WriteString(fmt.Sprintf("  otlp/%s:\n    endpoint: %s\n", exp.Name, exp.Endpoint))
			if exp.TLSInsecure != nil && *exp.TLSInsecure {
				b.WriteString("    tls:\n      insecure: true\n")
			}
		}
	}

	// Extensions
	b.WriteString(fmt.Sprintf("\nextensions:\n  health_check:\n    endpoint: 0.0.0.0:%d\n", HealthCheckPort))

	// Service pipelines
	b.WriteString("\nservice:\n  extensions: [health_check]\n  pipelines:\n")

	if hasLogs {
		b.WriteString("    logs:\n      receivers: [")
		b.WriteString(c.logReceiverName())
		b.WriteString("]\n      exporters: [")
		b.WriteString(c.exporterNames())
		b.WriteString("]\n")
	}

	if metricsEnabled {
		b.WriteString("    metrics:\n      receivers: [prometheus]\n      exporters: [")
		b.WriteString(c.exporterNames())
		b.WriteString("]\n")
	}

	return b.String()
}

func (c *component) exporterNames() string {
	var names []string
	for _, exp := range c.cfg.OTelCollector.Exporters {
		switch exp.Protocol {
		case operatorv1.OTelProtocolHTTP:
			names = append(names, fmt.Sprintf("otlphttp/%s", exp.Name))
		default:
			names = append(names, fmt.Sprintf("otlp/%s", exp.Name))
		}
	}
	return strings.Join(names, ", ")
}

func (c *component) logReceiverName() string {
	if c.cfg.LogForwarderProtocol == LogForwarderOTLP {
		return "otlp"
	}
	return "fluentdhttp"
}

func (c *component) logReceiverPort() int32 {
	if c.cfg.LogForwarderProtocol == LogForwarderOTLP {
		return OTLPHTTPPort
	}
	return FluentForwardPort
}

func (c *component) service() *corev1.Service {
	port := c.logReceiverPort()
	ports := []corev1.ServicePort{
		{
			Name:       c.logReceiverName(),
			Port:       port,
			TargetPort: intstr.FromInt32(port),
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
	return corev1.Container{
		Name:    OTelCollectorContainerName,
		Image:   c.image,
		Command: []string{"/usr/bin/otelcol", "--config=/etc/otel/config.yaml"},
		Ports: []corev1.ContainerPort{
			{Name: "fluentdhttp", ContainerPort: FluentForwardPort, Protocol: corev1.ProtocolTCP},
			{Name: "otlp-grpc", ContainerPort: OTLPGRPCPort, Protocol: corev1.ProtocolTCP},
			{Name: "otlp-http", ContainerPort: OTLPHTTPPort, Protocol: corev1.ProtocolTCP},
			{Name: "health", ContainerPort: HealthCheckPort, Protocol: corev1.ProtocolTCP},
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
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "config",
				MountPath: "/etc/otel",
				ReadOnly:  true,
			},
		},
	}
}

func (c *component) statefulSet() *appsv1.StatefulSet {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
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
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: OTelCollectorConfigMapName},
								},
							},
						},
					},
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
				Ports: networkpolicy.Ports(uint16(c.logReceiverPort())),
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

	metricsEnabled := c.cfg.OTelCollector.Metrics != nil &&
		c.cfg.OTelCollector.Metrics.Enabled != nil &&
		*c.cfg.OTelCollector.Metrics.Enabled == operatorv1.OTelMetricsEnable
	if metricsEnabled {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
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
