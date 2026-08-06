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
	"crypto/x509"
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	OpenTelemetryCollectorName                = render.OpenTelemetryCollectorName
	OpenTelemetryCollectorNamespace           = common.CalicoNamespace
	OpenTelemetryCollectorServiceAccountName  = OpenTelemetryCollectorName
	OpenTelemetryCollectorStatefulSetName     = OpenTelemetryCollectorName
	OpenTelemetryCollectorServiceName         = OpenTelemetryCollectorName
	OpenTelemetryCollectorConfigMapName       = OpenTelemetryCollectorName
	OpenTelemetryCollectorContainerName       = "otel-collector"
	OpenTelemetryCollectorPolicyName          = networkpolicy.CalicoComponentPolicyPrefix + OpenTelemetryCollectorName
	OpenTelemetryCollectorClusterRoleName     = OpenTelemetryCollectorName
	OpenTelemetryCollectorServerTLSSecretName = "otel-collector-tls"

	// OpenTelemetryCollectorCAConfigMapName is an optional user-supplied ConfigMap
	// holding the CA that signed the exporters' endpoints. It is loaded in addition
	// to the system root pool, so it is only needed for endpoints fronted by a
	// private CA. Mirrors the syslog-ca / splunk-ca convention.
	OpenTelemetryCollectorCAConfigMapName = "otel-collector-ca"
	// OpenTelemetryCollectorClientTLSSecretName is the user-supplied client keypair
	// presented to exporters that enable mutual TLS. Required when any exporter sets
	// mutualTLS. Mirrors the external Elasticsearch mTLS convention.
	OpenTelemetryCollectorClientTLSSecretName = "otel-collector-client-certs"

	// Mount outside /etc/otel: the config ConfigMap already owns that path.
	caVolumeName        = "exporter-ca"
	caMountPath         = "/certs/exporter-ca"
	clientTLSVolumeName = "exporter-client-tls"
	clientTLSMountPath  = "/certs/exporter-client"

	OTLPGRPCPort        = 4317
	OTLPHTTPPort        = 4318
	exporterPrefixHTTP  = "otlp_http"
	exporterPrefixGRPC  = "otlp_grpc"
	HealthCheckPort     = 13133
	InternalMetricsPort = 8888
	// MetricsPortName is referenced by the ServiceMonitor in the monitor render.
	MetricsPortName = render.OpenTelemetryCollectorMetricsPort

	DefaultMemoryLimit   = "512Mi"
	DefaultMemoryRequest = "128Mi"
	DefaultBatchMaxSize  = 2000 // keep each export under gRPC's 4MB default

	// memory_limiter budget, expressed as percentages so it tracks the container's
	// effective memory limit instead of assuming the default. Soft-limit at 80% of
	// the limit leaves the GC room to reclaim before the kubelet OOM-kills, and the
	// spike allowance is a quarter of that.
	memoryLimitPercent = 80
	memorySpikePercent = 25

	// Liveness is given a long boot grace so it cannot restart the collector while
	// it is still starting up; readiness is short so it takes traffic promptly.
	// Matches guardian, dex, manager and apiserver.
	livenessInitialDelaySeconds  = 90
	readinessInitialDelaySeconds = 10

	configHashAnnotation = "hash.operator.tigera.io/otel-collector-config"

	// DefaultTLSReloadInterval is a poll, not a watch, so keep it cheap. Certs
	// rotate roughly every two years and the operator starts rotating a month
	// before expiry; hourly is far more than enough.
	DefaultTLSReloadInterval = "1h"
)

type Configuration struct {
	PullSecrets   []*corev1.Secret
	OpenShift     bool
	Installation  *operatorv1.InstallationSpec
	OpenTelemetry *operatorv1.OpenTelemetrySpec
	// ReceiverTLSSecret is the server keypair for the OTLP receiver (mTLS termination).
	ReceiverTLSSecret certificatemanagement.KeyPairInterface
	TrustedCertBundle certificatemanagement.TrustedBundleRO
	// ExporterCA is the optional user-supplied CA ConfigMap for exporter endpoints
	// fronted by a private CA. Nil means endpoints are verified against the system
	// root pool alone.
	ExporterCA *corev1.ConfigMap
	// ExporterClientTLS is the user-supplied client keypair presented to exporters
	// that enable mutual TLS. Non-nil whenever any exporter sets mutualTLS.
	ExporterClientTLS *corev1.Secret
	// DomainEgressAllowed reports whether the license carries the
	// egress-access-control feature, without which NetworkPolicy cannot name a
	// destination by domain and egress rules fall back to port-only.
	DomainEgressAllowed bool
	// Disabled renders the component for removal instead of creation, so turning
	// the feature off cleans up after itself rather than leaving the collector
	// and its RBAC behind.
	Disabled bool
}

// Register the usages the receiver keypair must carry. The operator mints these
// certs with both usages (MakeServerCertForDuration sets ServerAuth and
// ClientAuth), and the rotation check regenerates any cert missing a registered
// usage, so declaring both matches what is actually issued.
func init() {
	certkeyusage.SetCertKeyUsage(OpenTelemetryCollectorServerTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

type component struct {
	cfg          *Configuration
	image        string
	renderedConf string
}

func OpenTelemetryCollector(cfg *Configuration) (render.Component, error) {
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
	if c.cfg.Disabled {
		// Nothing is owned by a CR we can rely on being deleted, so switching the
		// feature off has to explicitly tear its resources down.
		return nil, c.ownedObjects()
	}

	statefulSet := c.statefulSet()
	if c.cfg.OpenTelemetry.OpenTelemetryCollectorStatefulSet != nil {
		rcomp.ApplyStatefulSetOverrides(statefulSet, c.cfg.OpenTelemetry.OpenTelemetryCollectorStatefulSet)
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

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(OpenTelemetryCollectorNamespace, c.cfg.PullSecrets...)...)...)

	// The user creates these in the operator namespace; the collector runs in
	// calico-system, so they have to be copied across to be mountable.
	if c.cfg.ExporterCA != nil {
		objs = append(objs, configmap.ToRuntimeObjects(configmap.CopyToNamespace(OpenTelemetryCollectorNamespace, c.cfg.ExporterCA)...)...)
	}
	if c.cfg.ExporterClientTLS != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(OpenTelemetryCollectorNamespace, c.cfg.ExporterClientTLS)...)...)
	}

	return objs, nil
}

// ownedObjects lists every resource this component manages. Deletion reuses it so
// a resource added to the create path cannot be forgotten in the teardown path.
func (c *component) ownedObjects() []client.Object {
	return []client.Object{
		c.networkPolicy(),
		c.statefulSet(),
		c.service(),
		c.configMap(),
		c.clusterRoleBinding(),
		c.clusterRole(),
		c.serviceAccount(),
		// Copies of the user-supplied exporter TLS material. Named
		// deterministically, so they can be cleaned up without knowing whether the
		// user ever created the originals — otherwise they linger in
		// calico-system after the feature is switched off.
		&corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: OpenTelemetryCollectorCAConfigMapName, Namespace: OpenTelemetryCollectorNamespace},
		},
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: OpenTelemetryCollectorClientTLSSecretName, Namespace: OpenTelemetryCollectorNamespace},
		},
	}
}

func (c *component) Ready() bool {
	return true
}

func (c *component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: OpenTelemetryCollectorServiceAccountName, Namespace: OpenTelemetryCollectorNamespace},
	}
}

func (c *component) clusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: OpenTelemetryCollectorClusterRoleName,
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
			Name: OpenTelemetryCollectorClusterRoleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     OpenTelemetryCollectorClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      OpenTelemetryCollectorServiceAccountName,
				Namespace: OpenTelemetryCollectorNamespace,
			},
		},
	}
}

func (c *component) configMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: OpenTelemetryCollectorConfigMapName, Namespace: OpenTelemetryCollectorNamespace},
		Data: map[string]string{
			"config.yaml": c.renderedConf,
		},
	}
}

func (c *component) metricsEnabled() bool {
	return c.cfg.OpenTelemetry.MetricsEnabled()
}

func (c *component) hasLogs() bool {
	return c.cfg.OpenTelemetry.HasLogs()
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
	// TLSReloadInterval is how often the receiver re-reads its own keypair from
	// disk. Rotation happens on a ~2-year cycle, so this only needs to be well
	// under the operator's one-month pre-expiry rotation window.
	TLSReloadInterval string
	MetricsEnabled    bool
	MetricsCAFile     string
	// PrometheusFederateTarget is the host:port of the tigera-prometheus
	// authn-proxy fronting the /federate endpoint.
	PrometheusFederateTarget string
	Exporters                []exporterEntry
	ExporterNames            string
	// ExporterCAFile is the user-supplied CA for exporter endpoints. Empty means
	// the system root pool alone verifies them.
	ExporterCAFile string
	// ExporterClientCertFile / ExporterClientKeyFile are the client keypair
	// presented to exporters that enable mutual TLS.
	ExporterClientCertFile string
	ExporterClientKeyFile  string
	HealthCheckPort        int
	InternalMetricsPort    int
	MemoryLimitMiB         int
	MemorySpikeLimitMiB    int
	BatchMaxSize           int
}

type exporterEntry struct {
	Prefix    string
	Name      string
	Endpoint  string
	MutualTLS bool
	// Plaintext is set for http:// endpoints. OTLP backends are commonly exposed
	// without TLS in-cluster, and the scheme is how the user asks for that —
	// mirroring the Splunk output, where a plain-http endpoint does no TLS. There
	// is deliberately no field for "TLS on, verification off".
	Plaintext bool
}

//go:embed collector-config.yaml.template
var collectorConfigStr string

var collectorConfigTmpl = template.Must(template.New("config").Parse(collectorConfigStr))

func (c *component) collectorConfig() (string, error) {
	var exporters []exporterEntry
	var exporterNames []string
	for _, exp := range c.cfg.OpenTelemetry.Exporters {
		var prefix string
		if exp.Protocol == operatorv1.OpenTelemetryProtocolHTTP {
			prefix = exporterPrefixHTTP
		} else {
			prefix = exporterPrefixGRPC
		}
		exporters = append(exporters, exporterEntry{
			Prefix:    prefix,
			Name:      exp.Name,
			Endpoint:  exp.Endpoint,
			MutualTLS: exp.MutualTLS != nil && *exp.MutualTLS,
			Plaintext: strings.HasPrefix(exp.Endpoint, "http://"),
		})
		exporterNames = append(exporterNames, fmt.Sprintf("%s/%s", prefix, exp.Name))
	}

	memLimitMiB, memSpikeMiB := c.memoryLimiterMiB()
	data := configTemplateData{
		HasLogs:             c.hasLogs(),
		MetricsEnabled:      c.metricsEnabled(),
		Exporters:           exporters,
		ExporterNames:       strings.Join(exporterNames, ", "),
		HealthCheckPort:     HealthCheckPort,
		InternalMetricsPort: InternalMetricsPort,
		MemoryLimitMiB:      memLimitMiB,
		MemorySpikeLimitMiB: memSpikeMiB,
		BatchMaxSize:        DefaultBatchMaxSize,
	}

	if c.receiverTLSReady() {
		data.ReceiverTLS = true
		data.ReceiverCertFile = c.cfg.ReceiverTLSSecret.VolumeMountCertificateFilePath()
		data.ReceiverKeyFile = c.cfg.ReceiverTLSSecret.VolumeMountKeyFilePath()
		data.ReceiverClientCA = c.cfg.TrustedCertBundle.MountPath()
		data.TLSReloadInterval = DefaultTLSReloadInterval
	}

	// Exporter trust is deliberately kept off the operator's trusted bundle: that
	// bundle backs the receiver's client_ca_file, so folding public roots or a
	// user CA into it would make those CAs valid signers for inbound client certs.
	// include_system_ca_certs_pool lets each exporter add the system pool locally.
	if c.cfg.ExporterCA != nil {
		data.ExporterCAFile = fmt.Sprintf("%s/%s", caMountPath, corev1.TLSCertKey)
	}
	if c.cfg.ExporterClientTLS != nil {
		data.ExporterClientCertFile = fmt.Sprintf("%s/%s", clientTLSMountPath, corev1.TLSCertKey)
		data.ExporterClientKeyFile = fmt.Sprintf("%s/%s", clientTLSMountPath, corev1.TLSPrivateKeyKey)
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

// service is the StatefulSet's governing Service. It is deliberately a normal
// ClusterIP rather than headless: fluent-bit pushes to the VIP and each request
// lands on one replica, which is what spreads log ingest across them. If per-pod
// PVCs are added later a headless service will be wanted for stable pod DNS —
// give that a different name rather than making this one headless, or log
// load-balancing silently collapses onto a single replica.
func (c *component) service() *corev1.Service {
	ports := []corev1.ServicePort{
		{
			Name:       "otlp-http",
			Port:       OTLPHTTPPort,
			TargetPort: intstr.FromInt32(OTLPHTTPPort),
			Protocol:   corev1.ProtocolTCP,
		},
		{
			Name:       MetricsPortName,
			Port:       InternalMetricsPort,
			TargetPort: intstr.FromInt32(InternalMetricsPort),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OpenTelemetryCollectorServiceName,
			Namespace: OpenTelemetryCollectorNamespace,
			Labels:    map[string]string{"k8s-app": OpenTelemetryCollectorStatefulSetName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": OpenTelemetryCollectorStatefulSetName},
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

	if c.cfg.ExporterCA != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      caVolumeName,
			MountPath: caMountPath,
			ReadOnly:  true,
		})
	}

	if c.cfg.ExporterClientTLS != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      clientTLSVolumeName,
			MountPath: clientTLSMountPath,
			ReadOnly:  true,
		})
	}

	return corev1.Container{
		Name:    OpenTelemetryCollectorContainerName,
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
		ReadinessProbe:  healthProbe(readinessInitialDelaySeconds),
		LivenessProbe:   healthProbe(livenessInitialDelaySeconds),
		VolumeMounts:    volumeMounts,
	}
}

func healthProbe(initialDelaySeconds int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/",
				Port: intstr.FromInt32(HealthCheckPort),
			},
		},
		InitialDelaySeconds: initialDelaySeconds,
		PeriodSeconds:       10,
	}
}

// effectiveMemoryLimit is the container's memory limit after any StatefulSet
// override. Overrides are applied to the workload after the config is rendered,
// so without consulting them here a raised container limit would leave the
// collector still throttling itself at the default.
func (c *component) effectiveMemoryLimit() resource.Quantity {
	limit := resource.MustParse(DefaultMemoryLimit)
	ss := c.cfg.OpenTelemetry.OpenTelemetryCollectorStatefulSet
	if ss == nil || ss.Spec == nil || ss.Spec.Template == nil || ss.Spec.Template.Spec == nil {
		return limit
	}
	for _, container := range ss.Spec.Template.Spec.Containers {
		if container.Name != OpenTelemetryCollectorContainerName || container.Resources == nil {
			continue
		}
		if q, ok := container.Resources.Limits[corev1.ResourceMemory]; ok {
			return q
		}
	}
	return limit
}

// memoryLimiterMiB derives the memory_limiter values from the effective limit.
func (c *component) memoryLimiterMiB() (limitMiB, spikeMiB int) {
	limit := c.effectiveMemoryLimit()
	mib := int(limit.Value() / (1024 * 1024))
	limitMiB = mib * memoryLimitPercent / 100
	spikeMiB = limitMiB * memorySpikePercent / 100
	return limitMiB, spikeMiB
}

// podAnnotations rolls the pod whenever the rendered config or any trusted
// certificate changes. The config hash alone is not enough: the config embeds
// certificate *paths*, so a CA rotation leaves it byte-identical and nothing
// would restart the collector. HashAnnotations covers the PEM contents, which
// is what actually changes on rotation.
func (c *component) podAnnotations() map[string]string {
	annotations := map[string]string{
		configHashAnnotation: rmeta.AnnotationHash(c.renderedConf),
	}
	if c.cfg.TrustedCertBundle != nil {
		for k, v := range c.cfg.TrustedCertBundle.HashAnnotations() {
			annotations[k] = v
		}
	}
	if c.cfg.ReceiverTLSSecret != nil {
		annotations[c.cfg.ReceiverTLSSecret.HashAnnotationKey()] = c.cfg.ReceiverTLSSecret.HashAnnotationValue()
	}
	return annotations
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
					LocalObjectReference: corev1.LocalObjectReference{Name: OpenTelemetryCollectorConfigMapName},
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

	if c.cfg.ExporterCA != nil {
		volumes = append(volumes, corev1.Volume{
			Name: caVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: OpenTelemetryCollectorCAConfigMapName},
				},
			},
		})
	}

	if c.cfg.ExporterClientTLS != nil {
		volumes = append(volumes, corev1.Volume{
			Name: clientTLSVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: OpenTelemetryCollectorClientTLSSecretName,
				},
			},
		})
	}

	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OpenTelemetryCollectorStatefulSetName,
			Namespace: OpenTelemetryCollectorNamespace,
		},
		Spec: appsv1.StatefulSetSpec{
			// Pinned to one replica. Each replica independently federates the same
			// Prometheus targets and stamps its own service.instance.id, so every
			// series would be duplicated downstream. Scaling out needs a target
			// allocator (and anti-affinity/PDB) before it is safe.
			Replicas:    ptr.To(int32(1)),
			ServiceName: OpenTelemetryCollectorServiceName,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": OpenTelemetryCollectorStatefulSetName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        OpenTelemetryCollectorStatefulSetName,
					Labels:      map[string]string{"k8s-app": OpenTelemetryCollectorStatefulSetName},
					Annotations: c.podAnnotations(),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: OpenTelemetryCollectorServiceAccountName,
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
	egressRules := []v3.Rule{}

	// One rule per configured exporter, pinned to that exporter's host wherever
	// we're able to name it. There is deliberately no blanket allow on the OTLP
	// ports: the exporters below are the only egress destinations we need, and a
	// catch-all would let the collector reach any host on 4317/4318.
	for _, exp := range c.cfg.OpenTelemetry.Exporters {
		dest, ok := networkpolicy.ParseExternalDestination(exp.Endpoint)
		if !ok {
			continue
		}
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.ExternalDestinationEntityRule(dest, c.cfg.DomainEgressAllowed),
		})
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
		ObjectMeta: metav1.ObjectMeta{Name: OpenTelemetryCollectorPolicyName, Namespace: OpenTelemetryCollectorNamespace},
		Spec: v3.NetworkPolicySpec{
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(OpenTelemetryCollectorStatefulSetName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					// Only fluent-bit pushes logs at the OTLP receiver. mTLS already
					// gates this port, but the source selector keeps unrelated
					// workloads from reaching it at all.
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.FluentBitSourceEntityRule,
					Destination: v3.EntityRule{Ports: networkpolicy.Ports(OTLPHTTPPort)},
				},
				{
					// The collector's own metrics are served without TLS or authn, so
					// this port is restricted to Prometheus by source.
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.PrometheusSourceEntityRule,
					Destination: v3.EntityRule{Ports: networkpolicy.Ports(InternalMetricsPort)},
				},
			},
			Egress: egressRules,
		},
	}
}
