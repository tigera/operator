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

package render

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/resourcequota"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
	"github.com/tigera/operator/pkg/url"
)

const (
	LogCollectorNamespace        = "calico-system"
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
	FluentBitInputService                    = "calico-fluent-bit-http-input"
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
	ElasticsearchEksLogForwarderUserSecret   = "tigera-eks-log-forwarder-elasticsearch-access"
	EksLogForwarderSecret                    = "tigera-eks-log-forwarder-secret"
	EksLogForwarderAwsId                     = "aws-id"
	EksLogForwarderAwsKey                    = "aws-key"
	SplunkFluentBitTokenSecretName           = "logcollector-splunk-credentials"
	SplunkFluentBitSecretTokenKey            = "token"
	SplunkFluentBitSecretCertificateKey      = "ca.pem"
	SysLogPublicCADir                        = "/etc/pki/tls/certs/"
	SysLogPublicCertKey                      = "ca-bundle.crt"
	SysLogPublicCAPath                       = SysLogPublicCADir + SysLogPublicCertKey
	SyslogCAConfigMapName                    = "syslog-ca"

	// Constants for Linseed token volume mounting in managed clusters.
	LinseedTokenVolumeName = "linseed-token"
	LinseedTokenKey        = "token"
	LinseedTokenSubPath    = "token"
	LinseedTokenSecret     = "%s-tigera-linseed-token"
	LinseedVolumeMountPath = "/var/run/secrets/tigera.io/linseed/"
	LinseedTokenPath       = "/var/run/secrets/tigera.io/linseed/token"

	FluentBitConfConfigMapName       = "calico-fluent-bit-conf"
	EKSLogForwarderConfConfigMapName = "eks-log-forwarder-conf"

	legacyFluentdNamespace = "tigera-fluentd"

	fluentBitName        = "calico-fluent-bit"
	fluentBitWindowsName = "calico-fluent-bit-windows"

	FluentBitNodeName        = "calico-fluent-bit"
	fluentBitNodeWindowsName = "calico-fluent-bit-windows"

	EKSLogForwarderName          = "eks-log-forwarder"
	EKSLogForwarderTLSSecretName = "tigera-eks-log-forwarder-tls"

	PacketCaptureAPIRole        = "packetcapture-api-role"
	PacketCaptureAPIRoleBinding = "packetcapture-api-role-binding"
)

var FluentBitSourceEntityRule = v3.EntityRule{
	NamespaceSelector: fmt.Sprintf("name == '%s'", LogCollectorNamespace),
	Selector:          networkpolicy.KubernetesAppSelector(FluentBitNodeName, fluentBitNodeWindowsName),
}

var EKSLogForwarderEntityRule = networkpolicy.CreateSourceEntityRule(LogCollectorNamespace, EKSLogForwarderName)

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

func FluentBit(cfg *FluentBitConfiguration) Component {
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

func (c *fluentBitComponent) healthProbeHandler() corev1.ProbeHandler {
	return corev1.ProbeHandler{
		HTTPGet: &corev1.HTTPGetAction{
			Path: "/api/v1/health",
			Port: intstr.FromInt(FluentBitMetricsPort),
		},
	}
}

func (c *fluentBitComponent) securityContext(privileged bool) *corev1.SecurityContext {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return nil
	}
	return securitycontext.NewRootContext(privileged)
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
		&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder"}},
		&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "fluentd-metrics-windows", Namespace: legacyFluentdNamespace}},
		&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd-prometheus-tls", Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: EKSLogForwarderTLSSecretName, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: EksLogForwarderSecret, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: S3FluentBitSecretName, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: SplunkFluentBitTokenSecretName, Namespace: legacyFluentdNamespace}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf(LinseedTokenSecret, "fluentd-node"), Namespace: legacyFluentdNamespace}},
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

func (c *fluentBitComponent) nonClusterHostInputService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentBitInputService,
			Namespace: LogCollectorNamespace,
			Labels:    map[string]string{"k8s-app": c.fluentBitNodeName()},
		},
		// We do not treat this service as a headless service, as we want to ensure traffic is load-balanced. This is because:
		// - We have no guarantee that the client (voltron) will perform load balancing across the returned records. The
		//   golang dialer implementation appears to prefer the first record returned (see dialSerial in the go SDK)
		// - We have no guarantee that the DNS server will perform load-balancing or randomize the order of records returned
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.fluentBitNodeName()},
			Ports: []corev1.ServicePort{
				{
					Name:       FluentBitInputPortName,
					Port:       int32(FluentBitInputPort),
					TargetPort: intstr.FromInt(FluentBitInputPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *fluentBitComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	// For managed clusters, we must create a role binding to allow Linseed to manage access token secrets
	// in our namespace.
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-linseed",
			Namespace: LogCollectorNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     TigeraLinseedSecretsClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GuardianServiceAccountName,
				Namespace: GuardianNamespace,
			},
		},
	}
}

func (c *fluentBitComponent) externalLinseedService() *corev1.Service {
	// For managed clusters, we must create an external service for fluent-bit to forward requests to guardian.
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-linseed",
			Namespace: LogCollectorNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.svc.%s", GuardianServiceName, GuardianNamespace, c.cfg.ClusterDomain),
		},
	}
}

func (c *fluentBitComponent) Ready() bool {
	return true
}

func (c *fluentBitComponent) fluentBitResourceQuota() *corev1.ResourceQuota {
	criticalPriorityClasses := []string{NodePriorityClassName}
	return resourcequota.ResourceQuotaForPriorityClassScope(resourcequota.TigeraCriticalResourceQuotaName, LogCollectorNamespace, criticalPriorityClasses)
}

func (c *fluentBitComponent) s3CredentialSecret() *corev1.Secret {
	if c.cfg.S3Credential == nil {
		return nil
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      S3FluentBitSecretName,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string][]byte{
			S3KeyIdName:     c.cfg.S3Credential.KeyId,
			S3KeySecretName: c.cfg.S3Credential.KeySecret,
		},
	}
}

func (c *fluentBitComponent) splunkCredentialSecret() []*corev1.Secret {
	if c.cfg.SplkCredential == nil {
		return nil
	}
	return []*corev1.Secret{
		{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      SplunkFluentBitTokenSecretName,
				Namespace: LogCollectorNamespace,
			},
			Data: map[string][]byte{
				SplunkFluentBitSecretTokenKey: c.cfg.SplkCredential.Token,
			},
		},
	}
}

func (c *fluentBitComponent) fluentBitServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.fluentBitNodeName(), Namespace: LogCollectorNamespace},
	}
}

// packetCaptureApiRole creates a role in calico-system to allow pod/exec
// only from fluent-bit pods. Created by the operator for the PacketCapture API.
func (c *fluentBitComponent) packetCaptureApiRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCaptureAPIRole,
			Namespace: LogCollectorNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
		},
	}
}

// packetCaptureApiRoleBinding creates a role binding in calico-system for the PacketCapture API.
func (c *fluentBitComponent) packetCaptureApiRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCaptureAPIRoleBinding,
			Namespace: LogCollectorNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     PacketCaptureAPIRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PacketCaptureServiceAccountName,
				Namespace: PacketCaptureNamespace,
			},
		},
	}
}

func (c *fluentBitComponent) daemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0
	// The rationale for this setting is that while there is no need for fluent-bit to be available, we want to avoid
	// potentially negative consequences of an immediate roll-out on huge clusters.
	maxUnavailable := intstr.FromInt(10)

	annots := c.cfg.TrustedBundle.HashAnnotations()

	if c.cfg.FluentBitKeyPair != nil {
		annots[c.cfg.FluentBitKeyPair.HashAnnotationKey()] = c.cfg.FluentBitKeyPair.HashAnnotationValue()
	}
	if c.cfg.S3Credential != nil {
		annots[s3CredentialHashAnnotation] = rmeta.AnnotationHash(c.cfg.S3Credential)
	}
	if c.cfg.SplkCredential != nil {
		annots[splunkCredentialHashAnnotation] = rmeta.AnnotationHash(c.cfg.SplkCredential)
	}
	// Most LogCollector spec changes only alter the rendered ConfigMap (and the
	// config is subPath-mounted, which kubelet never live-updates), so hash the
	// rendered config into the pod template to force a rollout on change. This
	// also covers user filters, which are inlined into the config.
	annots[configHashAnnotation] = rmeta.AnnotationHash(c.renderFluentBitConf())
	var initContainers []corev1.Container
	if c.cfg.OSType == rmeta.OSTypeLinux {
		initContainers = append(initContainers, corev1.Container{
			Name:    "pos-migrator",
			Image:   c.image,
			Command: []string{"/usr/bin/pos-migrator"},
			Env: []corev1.EnvVar{
				{Name: "LOG_DIRS", Value: c.logDirsCSV()},
			},
			SecurityContext: c.securityContext(false),
			VolumeMounts: []corev1.VolumeMount{
				{MountPath: "/var/log/calico", Name: "var-log-calico"},
			},
		})
	} else {
		// Windows fluentd also kept tail positions (.pos files under the same
		// mounted log dir), so the cutover migration applies there too. The
		// Windows image ships the cross-compiled migrator; env overrides point
		// it at the c:-prefixed mounts.
		initContainers = append(initContainers, corev1.Container{
			Name:    "pos-migrator",
			Image:   c.image,
			Command: []string{c.path("/fluent-bit/pos-migrator.exe")},
			Env: []corev1.EnvVar{
				{Name: "POS_DIR", Value: c.path("/var/log/calico")},
				{Name: "DB_DIR", Value: c.path("/var/log/calico/calico-fluent-bit")},
				{Name: "LOG_DIRS", Value: c.logDirsCSV()},
			},
			SecurityContext: c.securityContext(false),
			VolumeMounts: []corev1.VolumeMount{
				{MountPath: c.path("/var/log/calico"), Name: "var-log-calico"},
			},
		})
	}
	if c.cfg.FluentBitKeyPair != nil && c.cfg.FluentBitKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.FluentBitKeyPair.InitContainer(LogCollectorNamespace, c.container().SecurityContext))
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			NodeSelector:                  map[string]string{},
			Tolerations:                   rmeta.TolerateAll,
			ImagePullSecrets:              secret.GetReferenceList(c.cfg.PullSecrets),
			TerminationGracePeriodSeconds: &terminationGracePeriod,
			InitContainers:                initContainers,
			Containers:                    []corev1.Container{c.container()},
			Volumes:                       c.volumes(),
			ServiceAccountName:            c.fluentBitNodeName(),
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.fluentBitNodeName(),
			Namespace: LogCollectorNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: *podTemplate,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}
	if c.cfg.LogCollector != nil {
		overrides := c.cfg.LogCollector.Spec.CalicoFluentBitDaemonSet
		if overrides == nil {
			// Deprecated alias: fluentdDaemonSet is honored for one release when
			// the new field is unset, per the API contract. Container entries
			// stored under the legacy "fluentd" name are translated to the
			// renamed container so resource overrides keep applying.
			overrides = translateLegacyFluentdOverrides(c.cfg.LogCollector.Spec.FluentdDaemonSet) //nolint:staticcheck // deliberate use of the deprecated alias field
		}
		if overrides != nil {
			rcomponents.ApplyDaemonSetOverrides(ds, overrides)
		}
	}
	setNodeCriticalPod(&(ds.Spec.Template))
	return ds
}

// translateLegacyFluentdOverrides maps a deprecated fluentdDaemonSet override
// onto the renamed calico-fluent-bit pod: container/init-container entries that
// still carry fluentd-era names (stored before the CRD enum was updated) are
// renamed so ApplyDaemonSetOverrides matches them.
func translateLegacyFluentdOverrides(legacy *operatorv1.FluentdDaemonSet) *operatorv1.FluentdDaemonSet {
	if legacy == nil {
		return nil
	}
	translated := legacy.DeepCopy()
	if translated.Spec == nil || translated.Spec.Template == nil || translated.Spec.Template.Spec == nil {
		return translated
	}
	for i, container := range translated.Spec.Template.Spec.Containers {
		if container.Name == "fluentd" {
			translated.Spec.Template.Spec.Containers[i].Name = "calico-fluent-bit"
		}
	}
	for i, container := range translated.Spec.Template.Spec.InitContainers {
		translated.Spec.Template.Spec.InitContainers[i].Name = strings.Replace(container.Name, "tigera-fluentd-prometheus-tls", FluentBitTLSSecretName, 1)
	}
	return translated
}

func (c *fluentBitComponent) container() corev1.Container {
	envs := c.envvars()
	volumeMounts := []corev1.VolumeMount{
		{MountPath: c.path("/var/log/calico"), Name: "var-log-calico"},
		{MountPath: c.path("/etc/fluent-bit/certs"), Name: certificatemanagement.TrustedCertConfigMapName},
	}
	if c.cfg.OSType == rmeta.OSTypeWindows {
		// Windows containers cannot mount a single file (no subPath file
		// mounts), so mount the whole ConfigMap as a directory. The Windows
		// image keeps its own files under C:\fluent-bit, so c:\etc\fluent-bit
		// shadows nothing.
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{MountPath: c.path("/etc/fluent-bit/conf"), Name: "fluent-bit-conf", ReadOnly: true})
	} else {
		// Mount only the rendered config as a single file (SubPath) so it does
		// not shadow the image's /etc/fluent-bit directory, which ships
		// plugins.conf, record_transformer.lua and the in_eks plugin.
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{MountPath: "/etc/fluent-bit/fluent-bit.yaml", Name: "fluent-bit-conf", SubPath: "fluent-bit.yaml", ReadOnly: true})
	}

	volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)

	if c.cfg.FluentBitKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.FluentBitKeyPair.VolumeMount(c.SupportedOSType()))
	}

	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: c.path(LinseedVolumeMountPath),
			})
	}

	return corev1.Container{
		Name:    "calico-fluent-bit",
		Image:   c.image,
		Command: []string{c.binPath()},
		Args:    []string{"-c", c.configPath()},
		Env:     envs,
		// On OpenShift Fluent Bit needs privileged access to access logs on host path volume
		SecurityContext: c.securityContext(c.cfg.Installation.KubernetesProvider.IsOpenShift()),
		VolumeMounts:    volumeMounts,
		StartupProbe:    c.startup(),
		LivenessProbe:   c.liveness(),
		ReadinessProbe:  c.readiness(),
		Ports: []corev1.ContainerPort{{
			Name:          "metrics-port",
			ContainerPort: FluentBitMetricsPort,
		}},
	}
}

func (c *fluentBitComponent) metricsService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.fluentBitMetricsServiceName(),
			Namespace: LogCollectorNamespace,
			Labels:    map[string]string{"k8s-app": c.fluentBitNodeName()},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.fluentBitNodeName()},
			// Important: "None" tells Kubernetes that we want a headless service with
			// no kube-proxy load balancer.  If we omit this then kube-proxy will render
			// a huge set of iptables rules for this service since there's an instance
			// on every node.
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       FluentBitMetricsPortName,
					Port:       int32(FluentBitMetricsPort),
					TargetPort: intstr.FromInt(FluentBitMetricsPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *fluentBitComponent) envvars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "NODENAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
	}
	// Additional stores are Linux-only (the Windows pipeline ships to Linseed
	// only, matching the fluentd Windows variant), so their credentials are too.
	if c.cfg.LogCollector.Spec.AdditionalStores != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		if s3 := c.cfg.LogCollector.Spec.AdditionalStores.S3; s3 != nil {
			// The standard AWS credential env vars, which fluent-bit's native s3
			// output reads via the AWS credential chain (the legacy AWS_KEY_ID /
			// AWS_SECRET_KEY names were fluentd-config-only and are read by
			// nothing in fluent-bit).
			envs = append(envs,
				corev1.EnvVar{
					Name: "AWS_ACCESS_KEY_ID",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: S3FluentBitSecretName},
							Key:                  S3KeyIdName,
						},
					},
				},
				corev1.EnvVar{
					Name: "AWS_SECRET_ACCESS_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: S3FluentBitSecretName},
							Key:                  S3KeySecretName,
						},
					},
				},
			)
		}
		if splunk := c.cfg.LogCollector.Spec.AdditionalStores.Splunk; splunk != nil {
			envs = append(envs,
				corev1.EnvVar{
					Name: "SPLUNK_HEC_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: SplunkFluentBitTokenSecretName},
							Key:                  SplunkFluentBitSecretTokenKey,
						},
					},
				},
			)
		}
	}
	return envs
}

func (c *fluentBitComponent) fluentBitConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.fluentBitConfConfigMapName(), Namespace: LogCollectorNamespace},
		Data:       map[string]string{"fluent-bit.yaml": c.renderFluentBitConf()},
	}
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
	{"audit.tsee", "/var/log/calico/audit/tsee-audit.log", "json"},
	{"audit.kube", "/var/log/calico/audit/kube-audit.log", "json"},
	{"bird", "/var/log/calico/bird/current", "bird_regex"},
	{"bird6", "/var/log/calico/bird6/current", "bird_regex"},
	{"ids.events", "/var/log/calico/ids/events.log", "json"},
	{"compliance.reports", "/var/log/calico/compliance/compliance.*.reports.log", "json"},
	{"policy_activity", "/var/log/calico/policy/policy_activity.log", "json"},
}

// windowsLogInputs match the fluentd Windows variant
// (fluentd/fluent_sources.conf.windows), which tails only flows and the audit
// logs.
var windowsLogInputs = []logInput{
	{"flows", "/var/log/calico/flowlogs/flows.log", "json"},
	{"audit.tsee", "/var/log/calico/audit/tsee-audit.log", "json"},
	{"audit.kube", "/var/log/calico/audit/kube-audit.log", "json"},
}

func (c *fluentBitComponent) logInputs() []logInput {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return windowsLogInputs
	}
	return linuxLogInputs
}

// logDirsCSV lists the tailed log directories (comma-separated) for the
// pos-migrator init container to pre-create: glob tail inputs (compliance) log
// a scan error on every refresh while their parent directory is missing, e.g.
// on clusters where the producing feature isn't enabled yet. Deriving the list
// from logInputs keeps a single source of truth for the tailed paths.
func (c *fluentBitComponent) logDirsCSV() string {
	var dirs []string
	seen := map[string]bool{}
	for _, in := range c.logInputs() {
		dir := c.path(in.path[:strings.LastIndex(in.path, "/")])
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return strings.Join(dirs, ",")
}

// linseedTags lists the tags shipped to Linseed: every tailed tag except
// ids.events and compliance.reports — those are deliberately not
// Linseed-bound (IDS events use a different ingestion path; compliance
// reports are S3-only). The non_cluster_* tags are produced by the
// voltron-facing http input relaying non-cluster host posts; hosts ship
// flow, DNS and policy activity logs.
func (c *fluentBitComponent) linseedTags() []string {
	var tags []string
	for _, in := range c.logInputs() {
		if in.tag == "ids.events" || in.tag == "compliance.reports" {
			continue
		}
		tags = append(tags, in.tag)
	}
	if c.cfg.NonClusterHost != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		tags = append(tags, "non_cluster_flows", "non_cluster_dns", "non_cluster_policy_activity")
	}
	return tags
}

// linseedBulkURI maps a tag to its Linseed bulk-ingestion URI. Voltron-relayed
// non_cluster_* tags post to the same path as their base tag.
func linseedBulkURI(tag string) string {
	tag = strings.TrimPrefix(tag, "non_cluster_")
	switch tag {
	case "runtime":
		return "/api/v1/runtime/reports/bulk"
	case "audit.tsee":
		return "/api/v1/audit/logs/ee/bulk"
	case "audit.kube":
		return "/api/v1/audit/logs/kube/bulk"
	case "bird", "bird6":
		return "/api/v1/bgp/logs/bulk"
	default:
		// flows, dns, l7, waf, policy_activity
		return fmt.Sprintf("/api/v1/%s/logs/bulk", tag)
	}
}

// splitEndpoint splits an https:// endpoint into the host and port fields
// fluent-bit's native net layer expects (the port defaults to 443). Plain
// string handling: pkg/url's ParseEndpoint rejects endpoints without an
// explicit port, and Linseed endpoints usually carry none.
func splitEndpoint(endpoint string) (string, int) {
	host := strings.TrimPrefix(endpoint, "https://")
	host = strings.TrimSuffix(host, "/")
	port := 443
	if i := strings.LastIndex(host, ":"); i >= 0 {
		if n, err := strconv.Atoi(host[i+1:]); err == nil {
			host, port = host[:i], n
		}
	}
	return host, port
}

// linseedHTTPOutput renders one built-in http output block shipping a tag's
// chunks to its Linseed bulk endpoint. The http output is plain C compiled
// into fluent-bit — no Go proxy plugin is involved — and `format json_lines`
// with the date key disabled produces exactly the NDJSON body Linseed's bulk
// APIs expect. The bearer token file is re-read on every request (a Tigera
// patch carried by the fluent-bit base build), so kubelet-rotated
// ServiceAccount tokens and operator-refreshed managed-cluster tokens are
// picked up without a restart. certPath/keyPath are the mTLS client keypair;
// storageLimit, when non-empty, caps this output's filesystem retry backlog.
func (c *fluentBitComponent) linseedHTTPOutput(tag, certPath, keyPath, storageLimit string) map[string]interface{} {
	host, port := splitEndpoint(relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant), c.cfg.ManagedCluster, true))
	out := map[string]interface{}{
		"name":   "http",
		"match":  tag,
		"host":   host,
		"port":   port,
		"uri":    linseedBulkURI(tag),
		"format": "json_lines",
		// One record per line, nothing else: Linseed parses each line as the
		// log document itself, so no synthetic date field is added.
		"json_date_key": false,
		"tls":           "on",
		"tls.verify":    "on",
		// tls.verify only checks the chain; hostname/SAN verification is a
		// separate knob that defaults off in fluent-bit. The Go plugin this
		// replaces verified hostnames (crypto/tls default), so keep parity.
		"tls.verify_hostname": "on",
		"tls.ca_file":         c.trustedBundlePath(),
		"tls.crt_file":        certPath,
		"tls.key_file":        keyPath,
		"bearer_token_file":   c.path(GetLinseedTokenPath(c.cfg.ManagedCluster)),
		// Retry failed chunks until they send instead of dropping them after
		// the default single retry; the filesystem storage bounds what can
		// accumulate during a Linseed outage.
		"retry_limit": "no_limits",
	}
	if storageLimit != "" {
		out["storage.total_limit_size"] = storageLimit
	}
	if c.cfg.Tenant != nil && c.cfg.ExternalElastic {
		out["header"] = fmt.Sprintf("x-tenant-id %s", c.cfg.Tenant.Spec.ID)
	}
	return out
}

// linseedStorageLimit sizes a tag's filesystem retry backlog: flow logs are
// the dominant volume and keep the budget the single shared output used to
// have; everything else is low-volume.
func linseedStorageLimit(tag string) string {
	if tag == "flows" || tag == "non_cluster_flows" {
		return "500M"
	}
	return "100M"
}

func (c *fluentBitComponent) renderFluentBitConf() string {
	caPath := c.trustedBundlePath()
	keyPath := c.keyPath()
	certPath := c.certPath()

	cfg := fluentBitConfig{
		Service: map[string]interface{}{
			"flush":       5,
			"log_level":   "info",
			"http_server": true,
			"http_port":   FluentBitMetricsPort,
			// Enable the /api/v1/health endpoint that the liveness/readiness/
			// startup probes hit (without this it returns 404 and pods never
			// become Ready).
			"health_check": true,
			// Filesystem buffering under the same hostPath-backed state dir as
			// the tail offset DBs, so buffered-but-unsent chunks survive pod
			// restarts (fluentd buffered to disk for up to 72h).
			"storage.path": c.path("/var/log/calico/calico-fluent-bit/storage"),
		},
		// Parsers referenced by the tail inputs. Defined inline so the config is
		// self-contained and does not depend on the image's parsers.conf.
		Parsers: []map[string]interface{}{
			{"name": "json", "format": "json"},
			{"name": "bird_regex", "format": "regex", "regex": `^(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d{5} bird: (?<message>.*)`},
		},
	}

	for _, in := range c.logInputs() {
		cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
			"name": "tail",
			"path": c.path(in.path),
			"tag":  in.tag,
			// Persist read offsets in SQLite under /var/log/calico/calico-fluent-bit
			// — the same directory the host rpm/deb package uses, and a subdir of the
			// already-mounted var-log-calico volume — so the tail resumes across
			// restarts instead of re-shipping from the head. The pos-migrator init
			// container seeds these DBs from the legacy fluentd .pos files at cutover;
			// read_from_head only applies to files with no prior offset (first install).
			"db":             c.path(fmt.Sprintf("/var/log/calico/calico-fluent-bit/in_tail_%s.db", in.tag)),
			"parser":         in.parser,
			"read_from_head": true,
			"storage.type":   "filesystem",
		})
	}

	if c.cfg.NonClusterHost != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
			"name":         "http",
			"listen":       "0.0.0.0",
			"port":         FluentBitInputPort,
			"tls":          "on",
			"tls.ca_file":  caPath,
			"tls.crt_file": certPath,
			"tls.key_file": keyPath,
			// Require a Tigera-CA-signed client certificate, like fluentd's http
			// source did (client_cert_auth true) — voltron presents its internal
			// client certificate on this hop.
			"tls.verify_client_cert": "on",
			"storage.type":           "filesystem",
		})
	}

	// Per-log-type transforms (host injection, flows @timestamp, audit name
	// derivation, BIRD ip_version + noise drop, etc.) are implemented in the
	// record_transformer.lua filter shipped in the image, keyed by tag.
	cfg.Pipeline.Filters = append(cfg.Pipeline.Filters, map[string]interface{}{
		"name":   "lua",
		"match":  "*",
		"script": c.luaScriptPath(),
		"call":   "record_transformer",
	})

	// User-provided flow/dns filters (from the fluent-bit-filters ConfigMap) are
	// inlined into the pipeline, replacing fluentd's config-include mechanism.
	// Each ConfigMap key holds a YAML list of fluent-bit filter entries.
	c.addUserFilters(&cfg)

	// One built-in http output per Linseed-bound tag: chunks are per-tag, so
	// an exact match per block routes every record to its bulk endpoint. The
	// per-tag split replaces the single out_linseed Go proxy output — the C
	// http output keeps the container free of Go proxy plugins.
	for _, tag := range c.linseedTags() {
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs,
			c.linseedHTTPOutput(tag, certPath, keyPath, linseedStorageLimit(tag)))
	}

	// Additional stores are Linux-only, matching the fluentd Windows variant
	// (Linseed only).
	if c.cfg.LogCollector.Spec.AdditionalStores != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		c.addS3Outputs(&cfg)
		c.addSyslogOutputs(&cfg)
		c.addSplunkOutputs(&cfg)
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Sprintf("# error rendering config: %v\n", err)
	}
	return string(out)
}

// parseUserFilter parses a user-provided filter snippet (the content of a
// fluent-bit-filters ConfigMap key) as a YAML list of fluent-bit filter maps.
func parseUserFilter(content string) ([]map[string]interface{}, error) {
	var filters []map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &filters); err != nil {
		return nil, err
	}
	return filters, nil
}

// InvalidKeys returns the names of the fluent-bit-filters ConfigMap keys whose
// content is non-empty but does not parse as a fluent-bit YAML filter list — for
// example a leftover fluentd <filter> block after an upgrade. addUserFilters skips
// these during render so the pipeline still starts; callers use this to surface the
// misconfiguration to the user without failing the whole LogCollector.
func (f *FluentBitFilters) InvalidKeys() []string {
	if f == nil {
		return nil
	}
	var bad []string
	for _, uf := range []struct{ name, content string }{
		{FluentBitFilterFlowName, f.Flow},
		{FluentBitFilterDNSName, f.DNS},
	} {
		if uf.content == "" {
			continue
		}
		if _, err := parseUserFilter(uf.content); err != nil {
			bad = append(bad, uf.name)
		}
	}
	return bad
}

// addUserFilters inlines the user-provided filter snippets into the pipeline.
// The fluent-bit-filters ConfigMap keys (flow, dns) each hold a YAML list of
// fluent-bit filter maps; entries without an explicit match are scoped to the
// key's log tag. Invalid YAML is skipped (and logged) rather than breaking the
// whole pipeline; the controller surfaces it as a TigeraStatus warning (see
// InvalidKeys).
func (c *fluentBitComponent) addUserFilters(cfg *fluentBitConfig) {
	if c.cfg.Filters == nil || c.cfg.OSType != rmeta.OSTypeLinux {
		return
	}
	for _, uf := range []struct{ content, tag string }{
		{c.cfg.Filters.Flow, "flows"},
		{c.cfg.Filters.DNS, "dns"},
	} {
		if uf.content == "" {
			continue
		}
		filters, err := parseUserFilter(uf.content)
		if err != nil {
			log.Error(err, "skipping invalid user filter content", "tag", uf.tag)
			continue
		}
		for _, f := range filters {
			if _, ok := f["match"]; !ok {
				if _, ok := f["match_regex"]; !ok {
					f["match"] = uf.tag
				}
			}
			cfg.Pipeline.Filters = append(cfg.Pipeline.Filters, f)
		}
	}
}

func (c *fluentBitComponent) addS3Outputs(cfg *fluentBitConfig) {
	s3 := c.cfg.LogCollector.Spec.AdditionalStores.S3
	if s3 == nil {
		return
	}
	// The log types fluentd archived to S3 (fluentd/outputs/out-s3-*.conf):
	// BGP, IDS events and policy activity were never S3-archived.
	tags := []string{"flows", "dns", "l7", "waf", "runtime", "audit.tsee", "audit.kube", "compliance.reports"}
	if s3.HostScope != nil && *s3.HostScope == operatorv1.HostScopeNonClusterOnly {
		// Matches fluentd's behavior: FORWARD_NON_CLUSTER_LOGS_TO_S3 only wired
		// S3 into the non-cluster flows path (ee_entrypoint.sh), not DNS or
		// policy activity. The tag is the one the http input derives from
		// voltron's /non-cluster-flows route.
		tags = []string{"non_cluster_flows"}
	}
	for _, tag := range tags {
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, map[string]interface{}{
			"name":                     "s3",
			"match":                    tag,
			"bucket":                   s3.BucketName,
			"region":                   s3.Region,
			"s3_key_format":            fmt.Sprintf("%s/%s/%%Y%%m%%d_$INDEX.gz", s3.BucketPath, tag),
			"total_file_size":          "10M",
			"upload_timeout":           fluentBitDefaultFlush,
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		})
	}
}

func (c *fluentBitComponent) addSyslogOutputs(cfg *fluentBitConfig) {
	syslog := c.cfg.LogCollector.Spec.AdditionalStores.Syslog
	if syslog == nil {
		return
	}
	proto, host, port, _ := url.ParseEndpoint(syslog.Endpoint)
	mode := proto
	var syslogTags []string
	for _, t := range syslog.LogTypes {
		switch t {
		case operatorv1.SyslogLogAudit:
			syslogTags = append(syslogTags, "audit.tsee", "audit.kube")
		case operatorv1.SyslogLogDNS:
			syslogTags = append(syslogTags, "dns")
		case operatorv1.SyslogLogFlows:
			syslogTags = append(syslogTags, "flows")
		case operatorv1.SyslogLogIDSEvents:
			syslogTags = append(syslogTags, "ids.events")
		}
	}
	for _, tag := range syslogTags {
		out := map[string]interface{}{
			"name":                   "syslog",
			"match":                  tag,
			"host":                   host,
			"port":                   port,
			"mode":                   mode,
			"syslog_format":          "rfc5424",
			"syslog_hostname_key":    "host",
			"syslog_appname_preset":  "tigera_secure",
			"syslog_severity_preset": "info",
			// The whole record is shipped as one JSON MSG, preserving fluentd
			// remote_syslog's `<format> @type json` wire format: the per-output
			// lua processor below packs the record into the `log` key, so other
			// outputs still see the unpacked record.
			"syslog_message_key": "log",
			"processors": map[string]interface{}{
				"logs": []map[string]interface{}{{
					"name":   "lua",
					"script": c.luaScriptPath(),
					"call":   "syslog_pack",
				}},
			},
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		}
		if syslog.Encryption == operatorv1.EncryptionTLS {
			out["mode"] = "tls"
			// `mode tls` only selects the framing; the tls property is what
			// actually enables TLS on the upstream connection.
			out["tls"] = "on"
			out["tls.verify"] = "on"
			if c.cfg.UseSyslogCertificate {
				// The user-provided syslog CA is part of the trusted bundle
				// (fluentd pointed SYSLOG_CA_FILE at the same bundle).
				out["tls.ca_file"] = c.trustedBundlePath()
			}
		}
		if syslog.PacketSize != nil {
			out["syslog_maxsize"] = *syslog.PacketSize
		}
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, out)
	}
}

func (c *fluentBitComponent) addSplunkOutputs(cfg *fluentBitConfig) {
	splunk := c.cfg.LogCollector.Spec.AdditionalStores.Splunk
	if splunk == nil {
		return
	}
	proto, host, port, _ := url.ParseEndpoint(splunk.Endpoint)
	// The log types fluentd forwarded to Splunk HEC
	// (fluentd/outputs/out-splunk-{flow,dns,l7,audit}.conf).
	for _, tag := range []string{"flows", "dns", "l7", "audit.tsee", "audit.kube"} {
		out := map[string]interface{}{
			"name":                     "splunk",
			"match":                    tag,
			"host":                     host,
			"port":                     port,
			"splunk_token":             "${SPLUNK_HEC_TOKEN}",
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		}
		// Honor the endpoint scheme like fluentd's SPLUNK_PROTOCOL did: an
		// http:// HEC endpoint stays plaintext, https:// gets verified TLS
		// against the trusted bundle (which carries any private CA).
		if proto != "http" {
			out["tls"] = "on"
			out["tls.verify"] = "on"
			out["tls.ca_file"] = c.trustedBundlePath()
		}
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, out)
	}
}

func (c *fluentBitComponent) trustedBundlePath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return certificatemanagement.TrustedCertBundleMountPathWindows
	}
	return c.cfg.TrustedBundle.MountPath()
}

func (c *fluentBitComponent) keyPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentBitKeyPair.GetName(), corev1.TLSPrivateKeyKey)
	}
	return c.cfg.FluentBitKeyPair.VolumeMountKeyFilePath()
}

func (c *fluentBitComponent) certPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentBitKeyPair.GetName(), corev1.TLSCertKey)
	}
	return c.cfg.FluentBitKeyPair.VolumeMountCertificateFilePath()
}

// The startup probe uses the same action as the liveness probe, but with
// a higher failure threshold and double the timeout to account for slow
// networks.
func (c *fluentBitComponent) startup() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     c.healthProbeHandler(),
		TimeoutSeconds:   c.probeTimeout,
		PeriodSeconds:    c.probePeriod,
		FailureThreshold: 10,
	}
}

func (c *fluentBitComponent) liveness() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:   c.healthProbeHandler(),
		TimeoutSeconds: c.probeTimeout,
		PeriodSeconds:  c.probePeriod,
	}
}

func (c *fluentBitComponent) readiness() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:   c.healthProbeHandler(),
		TimeoutSeconds: c.probeTimeout,
		PeriodSeconds:  c.probePeriod,
	}
}

func (c *fluentBitComponent) volumes() []corev1.Volume {
	dirOrCreate := corev1.HostPathDirectoryOrCreate

	volumes := []corev1.Volume{
		{
			Name: "var-log-calico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: c.volumeHostPath(),
					Type: &dirOrCreate,
				},
			},
		},
		{
			Name: "fluent-bit-conf",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: c.fluentBitConfConfigMapName(),
					},
				},
			},
		},
	}
	if c.cfg.FluentBitKeyPair != nil {
		volumes = append(volumes, c.cfg.FluentBitKeyPair.Volume())
	}
	if c.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						// Per-OS: the token controller provisions a secret per
						// ServiceAccount (calico-fluent-bit /
						// calico-fluent-bit-windows).
						SecretName: fmt.Sprintf(LinseedTokenSecret, c.fluentBitNodeName()),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
	}
	volumes = append(volumes, trustedBundleVolume(c.cfg.TrustedBundle))

	return volumes
}

func (c *fluentBitComponent) fluentBitClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.fluentBitName(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     c.fluentBitName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      c.fluentBitNodeName(),
				Namespace: LogCollectorNamespace,
			},
		},
	}
}

func (c *fluentBitComponent) fluentBitClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.fluentBitName(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Add write access to Linseed APIs.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flowlogs",
					"kube_auditlogs",
					"ee_auditlogs",
					"dnslogs",
					"l7logs",
					"events",
					"bgplogs",
					"waflogs",
					"runtimereports",
					"policyactivity",
				},
				Verbs: []string{"create"},
			},
		},
	}

	if c.cfg.Installation.KubernetesProvider.IsOpenShift() {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.Privileged},
		})
	}
	return role
}

func (c *fluentBitComponent) eksLogForwarderServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: EKSLogForwarderName, Namespace: LogCollectorNamespace},
	}
}

func (c *fluentBitComponent) eksLogForwarderSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EksLogForwarderSecret,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string][]byte{
			EksLogForwarderAwsId:  c.cfg.EKSConfig.AwsId,
			EksLogForwarderAwsKey: c.cfg.EKSConfig.AwsKey,
		},
	}
}

// renderEKSFluentBitConf renders the fluent-bit config for the eks-log-forwarder
// Deployment: a single in_eks input (the Go plugin polls CloudWatch, applies
// the EKS audit shaping itself, and resumes from the last Linseed-ingested
// timestamp on every process start) feeding the built-in http output that
// ships to Linseed. The in_eks plugin reads its CloudWatch/Linseed settings
// from the Deployment's env vars rather than plugin properties.
func (c *fluentBitComponent) renderEKSFluentBitConf() string {
	cfg := fluentBitConfig{
		Service: map[string]interface{}{
			"flush":        5,
			"log_level":    "info",
			"http_server":  true,
			"http_port":    FluentBitMetricsPort,
			"health_check": true,
			// Load the custom in_eks Go plugin shipped in the image. Without
			// this the `in_eks` input is an unknown plugin.
			"plugins_file": c.pluginsFilePath(),
		},
	}
	cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
		"name": "in_eks",
		"tag":  "audit.kube",
	})
	cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, c.linseedHTTPOutput(
		"audit.kube",
		c.cfg.EKSLogForwarderKeyPair.VolumeMountCertificateFilePath(),
		c.cfg.EKSLogForwarderKeyPair.VolumeMountKeyFilePath(),
		// No filesystem storage on this Deployment, so no backlog cap applies.
		""))

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Sprintf("# error rendering config: %v\n", err)
	}
	return string(out)
}

func (c *fluentBitComponent) eksConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: EKSLogForwarderConfConfigMapName, Namespace: LogCollectorNamespace},
		Data:       map[string]string{"fluent-bit.yaml": c.renderEKSFluentBitConf()},
	}
}

func (c *fluentBitComponent) eksLogForwarderDeployment() *appsv1.Deployment {
	annots := map[string]string{
		eksCloudwatchLogCredentialHashAnnotation: rmeta.AnnotationHash(c.cfg.EKSConfig),
		configHashAnnotation:                     rmeta.AnnotationHash(c.renderEKSFluentBitConf()),
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		// CloudWatch config, credentials — consumed by the in_eks input plugin
		// (fluent-bit/plugins/in_eks/pkg/config) and the AWS SDK credential chain.
		{Name: "EKS_CLOUDWATCH_LOG_GROUP", Value: c.cfg.EKSConfig.GroupName},
		{Name: "AWS_REGION", Value: c.cfg.EKSConfig.AwsRegion},
		{Name: "AWS_ACCESS_KEY_ID", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsId, false)},
		{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsKey, false)},
		// Linseed connection for the plugin's resume-point query (it asks
		// Linseed for the last ingested audit timestamp on startup).
		// Determine the namespace in which Linseed is running. For managed and standalone clusters, this is always the elasticsearch
		// namespace. For multi-tenant management clusters, this may vary.
		{Name: "LINSEED_ENDPOINT", Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant), c.cfg.ManagedCluster, true)},
		{Name: "LINSEED_CA_PATH", Value: c.trustedBundlePath()},
		{Name: "TLS_CRT_PATH", Value: c.cfg.EKSLogForwarderKeyPair.VolumeMountCertificateFilePath()},
		{Name: "TLS_KEY_PATH", Value: c.cfg.EKSLogForwarderKeyPair.VolumeMountKeyFilePath()},
		{Name: "LINSEED_TOKEN", Value: c.path(GetLinseedTokenPath(c.cfg.ManagedCluster))},
	}
	// The logcollector controller defaults these before render
	// (getEksCloudwatchLogConfig: prefix kube-apiserver-audit-, interval
	// 60), so in practice both env vars are always set. The guards are
	// defense in depth for other callers: rendering an empty prefix or a
	// zero interval would override the plugin's own defaults with a broken
	// setting (an empty prefix matches every stream in the group).
	if c.cfg.EKSConfig.StreamPrefix != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "EKS_CLOUDWATCH_LOG_STREAM_PREFIX", Value: c.cfg.EKSConfig.StreamPrefix})
	}
	if c.cfg.EKSConfig.FetchInterval > 0 {
		envVars = append(envVars, corev1.EnvVar{Name: "EKS_CLOUDWATCH_POLL_INTERVAL", Value: fmt.Sprintf("%ds", c.cfg.EKSConfig.FetchInterval)})
	}
	if c.cfg.Tenant != nil && c.cfg.ExternalElastic {
		envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
	}

	var eksLogForwarderReplicas int32 = 1

	tolerations := c.cfg.Installation.ControlPlaneTolerations
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EKSLogForwarderName,
			Namespace: LogCollectorNamespace,
			Labels: map[string]string{
				"k8s-app": EKSLogForwarderName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &eksLogForwarderReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": EKSLogForwarderName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      EKSLogForwarderName,
					Namespace: LogCollectorNamespace,
					Labels: map[string]string{
						"k8s-app": EKSLogForwarderName,
					},
					Annotations: annots,
				},
				Spec: corev1.PodSpec{
					Tolerations:        tolerations,
					ServiceAccountName: EKSLogForwarderName,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers: []corev1.Container{{
						Name:            EKSLogForwarderName,
						Image:           c.image,
						Command:         []string{c.binPath()},
						Args:            []string{"-c", c.configPath()},
						Env:             envVars,
						SecurityContext: c.securityContext(false),
						VolumeMounts:    c.eksLogForwarderVolumeMounts(),
						StartupProbe:    c.startup(),
						LivenessProbe:   c.liveness(),
						ReadinessProbe:  c.readiness(),
					}},
					Volumes: c.eksLogForwarderVolumes(),
				},
			},
		},
	}

	if c.cfg.LogCollector != nil {
		if overrides := c.cfg.LogCollector.Spec.EKSLogForwarderDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func trustedBundleVolume(bundle certificatemanagement.TrustedBundle) corev1.Volume {
	volume := bundle.Volume()
	// We mount the bundle under two names; the standard name and the name for the expected elastic cert.
	volume.ConfigMap.Items = []corev1.KeyToPath{
		{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: certificatemanagement.TrustedCertConfigMapKeyName},
		//nolint:staticcheck // Ignore SA1019 deprecated
		{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: certificatemanagement.LegacyTrustedCertConfigMapKeyName},
		{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: SplunkFluentBitSecretCertificateKey},
		{Key: certificatemanagement.RHELRootCertificateBundleName, Path: certificatemanagement.RHELRootCertificateBundleName},
	}
	return volume
}

func (c *fluentBitComponent) eksLogForwarderVolumeMounts() []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      certificatemanagement.TrustedCertConfigMapName,
			MountPath: c.path("/etc/fluent-bit/certs/"),
		},
		// Mount only the rendered config file (SubPath) so it does not shadow
		// the image's /etc/fluent-bit directory (plugins.conf etc.).
		{
			Name:      "fluent-bit-conf",
			MountPath: c.configPath(),
			SubPath:   "fluent-bit.yaml",
			ReadOnly:  true,
		},
	}
	volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)
	if c.cfg.EKSLogForwarderKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.EKSLogForwarderKeyPair.VolumeMount(c.SupportedOSType()))
	}

	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: c.path(LinseedVolumeMountPath),
			})
	}
	return volumeMounts
}

func (c *fluentBitComponent) eksLogForwarderVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		trustedBundleVolume(c.cfg.TrustedBundle),
		{
			Name: "fluent-bit-conf",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: EKSLogForwarderConfConfigMapName,
					},
				},
			},
		},
	}
	if c.cfg.EKSLogForwarderKeyPair != nil {
		volumes = append(volumes, c.cfg.EKSLogForwarderKeyPair.Volume())
	}

	if c.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, EKSLogForwarderName),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
	}
	return volumes
}

func (c *fluentBitComponent) eksLogForwarderClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: EKSLogForwarderName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     EKSLogForwarderName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      EKSLogForwarderName,
				Namespace: LogCollectorNamespace,
			},
		},
	}
}

func (c *fluentBitComponent) eksLogForwarderClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Add read access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"auditlogs",
			},
			Verbs: []string{"get"},
		},
		{
			// Add write access to Linseed APIs to flush eks kube audit logs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"kube_auditlogs",
			},
			Verbs: []string{"create"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: EKSLogForwarderName,
		},
		Rules: rules,
	}
}

func (c *fluentBitComponent) calicoSystemPolicy() *v3.NetworkPolicy {
	multiTenant := false
	tenantNamespace := ""
	if c.cfg.Tenant != nil {
		multiTenant = true
		tenantNamespace = c.cfg.Tenant.Namespace
	}
	policyHelper := networkpolicy.Helper(multiTenant, tenantNamespace)

	egressRules := []v3.Rule{}
	if c.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", GuardianNamespace),
				Selector:          networkpolicy.KubernetesAppSelector(GuardianServiceName),
				NotPorts:          networkpolicy.Ports(8080),
			},
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", ElasticsearchNamespace),
				Selector:          networkpolicy.KubernetesAppSelector("tigera-secure-es-gateway"),
				NotPorts:          networkpolicy.Ports(5554),
			},
		})
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", ElasticsearchNamespace),
				Selector:          networkpolicy.KubernetesAppSelector("tigera-linseed"),
				NotPorts:          networkpolicy.Ports(8444),
			},
		})
		egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Installation.KubernetesProvider.IsOpenShift())
	}
	egressRules = append(egressRules, v3.Rule{
		Action: v3.Allow,
	})

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   networkpolicy.PrometheusSourceEntityRule,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(FluentBitMetricsPort),
			},
		},
	}

	if c.cfg.NonClusterHost != nil {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   policyHelper.ManagerSourceEntityRule(),
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(FluentBitInputPort),
			},
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentBitPolicyName,
			Namespace: LogCollectorNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:                  &networkpolicy.HighPrecedenceOrder,
			Tier:                   networkpolicy.CalicoTierName,
			Selector:               networkpolicy.KubernetesAppSelector(FluentBitNodeName, fluentBitNodeWindowsName),
			ServiceAccountSelector: "",
			Types:                  []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:                ingressRules,
			Egress:                 egressRules,
		},
	}
}
