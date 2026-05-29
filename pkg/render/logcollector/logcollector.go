// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package logcollector

import (
	"crypto/x509"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/resourcequota"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

var log = logf.Log.WithName("render_logcollector")

const (
	// LogCollectorNamespace and the fluent-bit/EKS network-identity symbols below are
	// aliased from the render package, where they live to avoid a render -> logcollector
	// import cycle (Guardian/Manager reference them when building NetworkPolicies).
	LogCollectorNamespace        = render.LogCollectorNamespace
	FluentBitFilterConfigMapName = "fluent-bit-filters"
	FluentBitFilterFlowName      = "flow"
	FluentBitFilterDNSName       = "dns"
	S3FluentBitSecretName        = "log-collector-s3-credentials"
	S3KeyIdName                  = "key-id"
	S3KeySecretName              = "key-secret"

	// FluentBitTLSSecretName is the TLS secret used on all connections served by fluent-bit.
	FluentBitTLSSecretName                   = "calico-fluent-bit-tls"
	FluentBitMetricsService                  = "calico-fluent-bit-metrics"
	FluentBitMetricsServiceWindows           = "calico-fluent-bit-metrics-windows"
	FluentBitInputService                    = render.FluentBitInputService
	FluentBitMetricsPortName                 = "fluent-bit-metrics-port"
	FluentBitMetricsPort                     = 2020
	FluentBitInputPortName                   = "fluent-bit-input-port"
	FluentBitInputPort                       = 9880
	FluentBitPolicyName                      = networkpolicy.CalicoComponentPolicyPrefix + "allow-calico-fluent-bit"
	configHashAnnotation                     = "hash.operator.tigera.io/fluent-bit-config"
	s3CredentialHashAnnotation               = "hash.operator.tigera.io/s3-credentials"
	splunkCredentialHashAnnotation           = "hash.operator.tigera.io/splunk-credentials"
	eksCloudwatchLogCredentialHashAnnotation = "hash.operator.tigera.io/eks-cloudwatch-log-credentials"
	fluentBitDefaultFlush                    = "5s"
	EksLogForwarderSecret                    = "tigera-eks-log-forwarder-secret"
	EksLogForwarderAwsId                     = "aws-id"
	EksLogForwarderAwsKey                    = "aws-key"
	SplunkFluentBitTokenSecretName           = "logcollector-splunk-credentials"
	SplunkFluentBitSecretTokenKey            = "token"
	SplunkFluentBitSecretCertificateKey      = render.SplunkFluentBitSecretCertificateKey
	SysLogPublicCADir                        = "/etc/pki/tls/certs/"
	SysLogPublicCertKey                      = "ca-bundle.crt"
	SysLogPublicCAPath                       = SysLogPublicCADir + SysLogPublicCertKey
	SyslogCAConfigMapName                    = "syslog-ca"

	// Constants for Linseed token volume mounting in managed clusters.
	LinseedTokenVolumeName = render.LinseedTokenVolumeName
	LinseedTokenKey        = render.LinseedTokenKey
	LinseedTokenSubPath    = render.LinseedTokenSubPath
	LinseedTokenSecret     = render.LinseedTokenSecret
	LinseedVolumeMountPath = render.LinseedVolumeMountPath
	LinseedTokenPath       = render.LinseedTokenPath

	FluentBitConfConfigMapName       = "calico-fluent-bit-conf"
	EKSLogForwarderConfConfigMapName = "eks-log-forwarder-conf"

	legacyFluentdNamespace = "tigera-fluentd"

	fluentBitName        = "calico-fluent-bit"
	fluentBitWindowsName = "calico-fluent-bit-windows"

	FluentBitNodeName        = render.FluentBitNodeName
	fluentBitNodeWindowsName = render.FluentBitNodeWindowsName

	EKSLogForwarderName          = render.EKSLogForwarderName
	EKSLogForwarderTLSSecretName = "tigera-eks-log-forwarder-tls"

	PacketCaptureAPIRole        = "packetcapture-api-role"
	PacketCaptureAPIRoleBinding = "packetcapture-api-role-binding"
)

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(FluentBitTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(EKSLogForwarderTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

type FluentBitFilters struct {
	Flow string
	DNS  string
}

type S3Credential struct {
	KeyId     []byte
	KeySecret []byte
}

type SplunkCredential struct {
	Token []byte
}

func FluentBit(cfg *FluentBitConfiguration) render.Component {
	return &fluentBitComponent{
		cfg:          cfg,
		probeTimeout: 10,
		probePeriod:  60,
	}
}

type EksCloudwatchLogConfig struct {
	AwsId         []byte
	AwsKey        []byte
	AwsRegion     string
	GroupName     string
	StreamPrefix  string
	FetchInterval int32
}

// FluentBitConfiguration contains all the config information needed to render the component.
type FluentBitConfiguration struct {
	LogCollector     *operatorv1.LogCollector
	S3Credential     *S3Credential
	SplkCredential   *SplunkCredential
	Filters          *FluentBitFilters
	EKSConfig        *EksCloudwatchLogConfig
	PullSecrets      []*corev1.Secret
	Installation     *operatorv1.InstallationSpec
	ClusterDomain    string
	OSType           rmeta.OSType
	FluentBitKeyPair certificatemanagement.KeyPairInterface
	TrustedBundle    certificatemanagement.TrustedBundle
	ManagedCluster   bool

	// Set if running as a multi-tenant management cluster. Configures the management cluster's
	// own fluent-bit daemonset.
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	// Whether to use User provided certificate or not.
	UseSyslogCertificate bool

	// EKSLogForwarderKeyPair contains the certificate presented by EKS LogForwarder when communicating with Linseed
	EKSLogForwarderKeyPair certificatemanagement.KeyPairInterface

	PacketCapture *operatorv1.PacketCaptureAPI

	NonClusterHost *operatorv1.NonClusterHost

	// LicenseExpired indicates the license has expired and fluent-bit DaemonSet should be removed.
	LicenseExpired bool

	OTelCollectorEnabled bool
}

type fluentBitComponent struct {
	cfg          *FluentBitConfiguration
	image        string
	probeTimeout int32
	probePeriod  int32
}

func (c *fluentBitComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	if c.cfg.OSType == rmeta.OSTypeWindows {
		var err error
		c.image, err = components.GetReference(components.ComponentFluentBitWindows, reg, path, prefix, is)
		return err
	}

	var err error
	c.image, err = components.GetReference(components.ComponentFluentBit, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return err
}

func (c *fluentBitComponent) SupportedOSType() rmeta.OSType {
	return c.cfg.OSType
}

func (c *fluentBitComponent) fluentBitName() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fluentBitWindowsName
	}
	return fluentBitName
}

func (c *fluentBitComponent) fluentBitNodeName() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fluentBitNodeWindowsName
	}
	return FluentBitNodeName
}

// Use different service names depending on the OS type ("calico-fluent-bit-metrics"
// vs "calico-fluent-bit-metrics-windows") in order to help identify which OS daemonset
// we are referring to.
func (c *fluentBitComponent) fluentBitMetricsServiceName() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return FluentBitMetricsServiceWindows
	}
	return FluentBitMetricsService
}

func (c *fluentBitComponent) volumeHostPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return "c:/TigeraCalico"
	}
	return "/var/log/calico"
}

func (c *fluentBitComponent) path(path string) string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		// Use c: path prefix for windows.
		return "c:" + path
	}
	// For linux just leave the path as-is.
	return path
}

// Image-layout paths. The Linux image ships fluent-bit at /usr/bin with its
// support files under /etc/fluent-bit; the Windows image (Dockerfile-windows)
// ships everything under C:\fluent-bit.
func (c *fluentBitComponent) binPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return "c:/fluent-bit/fluent-bit.exe"
	}
	return "/usr/bin/fluent-bit"
}

// pluginsFilePath is the loader config for the in_eks Go plugin shipped in
// the Linux image. The Windows image carries no Go plugins, so the Windows
// configs never reference it.
func (c *fluentBitComponent) pluginsFilePath() string {
	return "/etc/fluent-bit/plugins.conf"
}

func (c *fluentBitComponent) luaScriptPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return "c:/fluent-bit/record_transformer.lua"
	}
	return "/etc/fluent-bit/record_transformer.lua"
}

// configPath is where the container reads the rendered config: a subPath file
// mount on Linux, a directory mount on Windows (which cannot mount single
// files).
func (c *fluentBitComponent) configPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return "c:/etc/fluent-bit/conf/fluent-bit.yaml"
	}
	return "/etc/fluent-bit/fluent-bit.yaml"
}

// fluentBitConfConfigMapName is OS-suffixed: on mixed clusters the Linux and
// Windows components each render their own config (different paths and input
// sets), and a shared name would make the two renders overwrite each other.
func (c *fluentBitComponent) fluentBitConfConfigMapName() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return FluentBitConfConfigMapName + "-windows"
	}
	return FluentBitConfConfigMapName
}

func (c *fluentBitComponent) Objects() ([]client.Object, []client.Object) {
	var objs, toDelete []client.Object
	objs = append(objs, c.calicoSystemPolicy())
	objs = append(objs, c.metricsService())
	objs = append(objs, c.fluentBitConfigMap())

	// allow-tigera Tier was renamed to calico-system
	toDelete = append(toDelete, networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("allow-calico-fluent-bit", LogCollectorNamespace))

	// Clean up legacy fluentd resources from the old namespace.
	toDelete = append(toDelete,
		&appsv1.DaemonSet{TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-node", Namespace: legacyFluentdNamespace}},
		&appsv1.DaemonSet{TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-node-windows", Namespace: legacyFluentdNamespace}},
		&appsv1.Deployment{TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder", Namespace: legacyFluentdNamespace}},
		&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-metrics", Namespace: legacyFluentdNamespace}},
		&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-http-input", Namespace: legacyFluentdNamespace}},
		&corev1.ServiceAccount{TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-node", Namespace: legacyFluentdNamespace}},
		&corev1.ServiceAccount{TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-node-windows", Namespace: legacyFluentdNamespace}},
		&corev1.ServiceAccount{TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder", Namespace: legacyFluentdNamespace}},
		&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd-windows"}},
		&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd-windows"}},
		// Note: the eks-log-forwarder ClusterRole/ClusterRoleBinding are NOT
		// deleted here — they are cluster-scoped, keep their fluentd-era names,
		// and are reused (updated in place) by the fluent-bit EKS forwarder
		// render. Deleting them would fight the create processed earlier in the
		// same reconcile and leave the forwarder without Linseed RBAC.
		&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-metrics-windows", Namespace: legacyFluentdNamespace}},
		&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd-prometheus-tls", Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: EKSLogForwarderTLSSecretName, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: EksLogForwarderSecret, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: S3FluentBitSecretName, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: SplunkFluentBitTokenSecretName, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf(LinseedTokenSecret, "fluentd-node"), Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf(LinseedTokenSecret, "fluentd-node-windows"), Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf(LinseedTokenSecret, "eks-log-forwarder"), Namespace: legacyFluentdNamespace}},
		&corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-filters", Namespace: legacyFluentdNamespace}},
		&rbacv1.Role{TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: PacketCaptureAPIRole, Namespace: legacyFluentdNamespace}},
		&rbacv1.RoleBinding{TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: PacketCaptureAPIRoleBinding, Namespace: legacyFluentdNamespace}},
		&corev1.ResourceQuota{TypeMeta: metav1.TypeMeta{Kind: "ResourceQuota", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: resourcequota.TigeraCriticalResourceQuotaName, Namespace: legacyFluentdNamespace}},
		// The namespace itself goes last so the resources above are removed
		// individually first (no finalizer surprises) on clusters upgrading from
		// the fluentd era.
		&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: legacyFluentdNamespace}},
	)

	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		// We do this only for GKE as other providers don't (yet?)
		// automatically add resource quota that constrains whether
		// components that are marked cluster or node critical
		// can be scheduled.
		objs = append(objs, c.fluentBitResourceQuota())
	}
	if c.cfg.S3Credential != nil {
		objs = append(objs, c.s3CredentialSecret())
	}
	if c.cfg.SplkCredential != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(LogCollectorNamespace, c.splunkCredentialSecret()...)...)...)
	}
	// User filters are inlined into the rendered config (addUserFilters); the
	// copy of the filters ConfigMap an earlier iteration rendered into
	// calico-system is no longer used.
	toDelete = append(toDelete,
		&corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: FluentBitFilterConfigMapName, Namespace: LogCollectorNamespace}})
	if c.cfg.EKSConfig != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		objs = append(objs,
			c.eksLogForwarderClusterRole(),
			c.eksLogForwarderClusterRoleBinding())

		objs = append(objs, c.eksLogForwarderServiceAccount(),
			c.eksLogForwarderSecret(),
			c.eksConfigMap(),
			c.eksLogForwarderDeployment())
	}

	// Add in the cluster role and binding.
	objs = append(objs,
		c.fluentBitClusterRole(),
		c.fluentBitClusterRoleBinding(),
	)
	if c.cfg.ManagedCluster {
		objs = append(objs, c.externalLinseedService())
		objs = append(objs, c.externalLinseedRoleBinding())
	} else {
		toDelete = append(toDelete, c.externalLinseedService())
		toDelete = append(toDelete, c.externalLinseedRoleBinding())
	}

	objs = append(objs, c.fluentBitServiceAccount())
	if c.cfg.PacketCapture != nil {
		objs = append(objs, c.packetCaptureApiRole(), c.packetCaptureApiRoleBinding())
	}

	if c.cfg.LicenseExpired {
		toDelete = append(toDelete, c.daemonset())
	} else {
		objs = append(objs, c.daemonset())
	}

	if c.cfg.OSType == rmeta.OSTypeLinux {
		if c.cfg.NonClusterHost != nil {
			objs = append(objs, c.nonClusterHostInputService())
		} else {
			// Clean up the input service when the NonClusterHost resource is
			// removed; the rendered config drops the http input at the same time.
			toDelete = append(toDelete, c.nonClusterHostInputService())
		}
	}

	return objs, toDelete
}

func (c *fluentBitComponent) Ready() bool {
	return true
}

type fluentBitConfig struct {
	Service  map[string]interface{}   `json:"service"`
	Parsers  []map[string]interface{} `json:"parsers,omitempty"`
	Pipeline fluentBitPipeline        `json:"pipeline"`
	Plugins  []map[string]interface{} `json:"plugins,omitempty"`
}

type fluentBitPipeline struct {
	Inputs  []map[string]interface{} `json:"inputs"`
	Filters []map[string]interface{} `json:"filters,omitempty"`
	Outputs []map[string]interface{} `json:"outputs"`
}

// logInput is one tail input: the canonical tag and the file the producing
// component writes.
type logInput struct {
	tag, path, parser string
}

// linuxLogInputs are the log files the Linux daemonset tails. The paths are
// the producers' output paths, matching the authoritative defaults the fluentd
// image carried (fluentd/Dockerfile ENV *_LOG_FILE) — felix, BIRD, the
// apiserver audit policy, intrusion detection, compliance and the runtime
// security agent all keep writing to the same locations.
var linuxLogInputs = []logInput{
	{"flows", "/var/log/calico/flowlogs/flows.log", "json"},
	{"dns", "/var/log/calico/dnslogs/dns.log", "json"},
	{"l7", "/var/log/calico/l7logs/l7.log", "json"},
	{"waf", "/var/log/calico/waf/waf.log", "json"},
	{"runtime", "/var/log/calico/runtime-security/report.log", "json"},
	{"audit.tsee", "/var/log/calico/audit/tsee-audit.log", "json_audit"},
	{"audit.kube", "/var/log/calico/audit/kube-audit.log", "json_audit"},
	{"bird", "/var/log/calico/bird/current", "bird_regex"},
	{"bird6", "/var/log/calico/bird6/current", "bird_regex"},
	{"ids.events", "/var/log/calico/ids/events.log", "json_ids_events"},
	{"compliance.reports", "/var/log/calico/compliance/compliance.*.reports.log", "json"},
	{"policy_activity", "/var/log/calico/policy/policy_activity.log", "json"},
}

// windowsLogInputs match the fluentd Windows variant
// (fluentd/fluent_sources.conf.windows), which tails only flows and the audit
// logs.
var windowsLogInputs = []logInput{
	{"flows", "/var/log/calico/flowlogs/flows.log", "json"},
	{"audit.tsee", "/var/log/calico/audit/tsee-audit.log", "json_audit"},
	{"audit.kube", "/var/log/calico/audit/kube-audit.log", "json_audit"},
}
