// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
	"fmt"

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
	LogCollectorNamespace      = "tigera-fluentd"
	FluentdFilterConfigMapName = "fluentd-filters"
	FluentdFilterFlowName      = "flow"
	FluentdFilterDNSName       = "dns"
	S3FluentdSecretName        = "log-collector-s3-credentials"
	S3KeyIdName                = "key-id"
	S3KeySecretName            = "key-secret"

	// FluentdPrometheusTLSSecretName is the name of the secret containing the key pair fluentd presents to identify itself.
	// Somewhat confusingly, this is named the prometheus TLS key pair because that was the first
	// use-case for this credential. However, it is used on all TLS connections served by fluentd.
	FluentdPrometheusTLSSecretName           = "tigera-fluentd-prometheus-tls"
	FluentdMetricsService                    = "fluentd-metrics"
	FluentdMetricsServiceWindows             = "fluentd-metrics-windows"
	FluentdMetricsPortName                   = "fluentd-metrics-port"
	FluentdMetricsPort                       = 9081
	FluentdPolicyName                        = networkpolicy.TigeraComponentPolicyPrefix + "allow-fluentd-node"
	filterHashAnnotation                     = "hash.operator.tigera.io/fluentd-filters"
	s3CredentialHashAnnotation               = "hash.operator.tigera.io/s3-credentials"
	splunkCredentialHashAnnotation           = "hash.operator.tigera.io/splunk-credentials"
	eksCloudwatchLogCredentialHashAnnotation = "hash.operator.tigera.io/eks-cloudwatch-log-credentials"
	fluentdDefaultFlush                      = "5s"
	ElasticsearchEksLogForwarderUserSecret   = "tigera-eks-log-forwarder-elasticsearch-access"
	EksLogForwarderSecret                    = "tigera-eks-log-forwarder-secret"
	EksLogForwarderAwsId                     = "aws-id"
	EksLogForwarderAwsKey                    = "aws-key"
	SplunkFluentdTokenSecretName             = "logcollector-splunk-credentials"
	SplunkFluentdSecretTokenKey              = "token"
	SplunkFluentdSecretCertificateKey        = "ca.pem"
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

	fluentdName        = "tigera-fluentd"
	fluentdWindowsName = "tigera-fluentd-windows"

	FluentdNodeName        = "fluentd-node"
	fluentdNodeWindowsName = "fluentd-node-windows"

	EKSLogForwarderName          = "eks-log-forwarder"
	EKSLogForwarderTLSSecretName = "tigera-eks-log-forwarder-tls"

	PacketCaptureAPIRole        = "packetcapture-api-role"
	PacketCaptureAPIRoleBinding = "packetcapture-api-role-binding"
)

var FluentdSourceEntityRule = v3.EntityRule{
	NamespaceSelector: fmt.Sprintf("name == '%s'", LogCollectorNamespace),
	Selector:          networkpolicy.KubernetesAppSelector(FluentdNodeName, fluentdNodeWindowsName),
}

var EKSLogForwarderEntityRule = networkpolicy.CreateSourceEntityRule(LogCollectorNamespace, EKSLogForwarderName)

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(FluentdPrometheusTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(EKSLogForwarderTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

type FluentdFilters struct {
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

func Fluentd(cfg *FluentdConfiguration) Component {
	return &fluentdComponent{
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

// FluentdConfiguration contains all the config information needed to render the component.
type FluentdConfiguration struct {
	LogCollector   *operatorv1.LogCollector
	S3Credential   *S3Credential
	SplkCredential *SplunkCredential
	Filters        *FluentdFilters
	// ESClusterConfig is only populated for when EKSConfig
	// is also defined
	ESClusterConfig *relasticsearch.ClusterConfig
	EKSConfig       *EksCloudwatchLogConfig
	PullSecrets     []*corev1.Secret
	Installation    *operatorv1.InstallationSpec
	ClusterDomain   string
	OSType          rmeta.OSType
	FluentdKeyPair  certificatemanagement.KeyPairInterface
	TrustedBundle   certificatemanagement.TrustedBundle
	ManagedCluster  bool

	// Set if running as a multi-tenant management cluster. Configures the management cluster's
	// own fluentd daemonset.
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	// Whether to use User provided certificate or not.
	UseSyslogCertificate bool

	// EKSLogForwarderKeyPair contains the certificate presented by EKS LogForwarder when communicating with Linseed
	EKSLogForwarderKeyPair certificatemanagement.KeyPairInterface

	PacketCapture *operatorv1.PacketCaptureAPI
}

type fluentdComponent struct {
	cfg          *FluentdConfiguration
	image        string
	probeTimeout int32
	probePeriod  int32
}

func (c *fluentdComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	if c.cfg.OSType == rmeta.OSTypeWindows {
		var err error
		c.image, err = components.GetReference(components.ComponentFluentdWindows, reg, path, prefix, is)
		return err
	}

	var err error
	c.image, err = components.GetReference(components.ComponentFluentd, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return err
}

func (c *fluentdComponent) SupportedOSType() rmeta.OSType {
	return c.cfg.OSType
}

func (c *fluentdComponent) fluentdName() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fluentdWindowsName
	}
	return fluentdName
}

func (c *fluentdComponent) fluentdNodeName() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fluentdNodeWindowsName
	}
	return FluentdNodeName
}

// Use different service names depending on the OS type ("fluentd-metrics"
// vs "fluentd-metrics-windows") in order to help identify which OS daemonset
// we are referring to.
func (c *fluentdComponent) fluentdMetricsServiceName() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return FluentdMetricsServiceWindows
	}
	return FluentdMetricsService
}

func (c *fluentdComponent) readinessCmd() []string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		// On Windows, we rely on bash via msys2 installed by the fluentd base image.
		return []string{`c:\ruby\msys64\usr\bin\bash.exe`, `-lc`, `/c/bin/readiness.sh`}
	}
	return []string{"sh", "-c", "/bin/readiness.sh"}
}

func (c *fluentdComponent) livenessCmd() []string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		// On Windows, we rely on bash via msys2 installed by the fluentd base image.
		return []string{`c:\ruby\msys64\usr\bin\bash.exe`, `-lc`, `/c/bin/liveness.sh`}
	}
	return []string{"sh", "-c", "/bin/liveness.sh"}
}

func (c *fluentdComponent) securityContext(privileged bool) *corev1.SecurityContext {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return nil
	}
	return securitycontext.NewRootContext(privileged)
}

func (c *fluentdComponent) volumeHostPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return "c:/TigeraCalico"
	}
	return "/var/log/calico"
}

func (c *fluentdComponent) path(path string) string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		// Use c: path prefix for windows.
		return "c:" + path
	}
	// For linux just leave the path as-is.
	return path
}

func (c *fluentdComponent) Objects() ([]client.Object, []client.Object) {
	var objs, toDelete []client.Object
	objs = append(objs, CreateNamespace(LogCollectorNamespace, c.cfg.Installation.KubernetesProvider, PSSPrivileged, c.cfg.Installation.Azure))
	objs = append(objs, c.allowTigeraPolicy())
	objs = append(objs, CreateOperatorSecretsRoleBinding(LogCollectorNamespace))
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(LogCollectorNamespace, c.cfg.PullSecrets...)...)...)
	objs = append(objs, c.metricsService())

	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		// We do this only for GKE as other providers don't (yet?)
		// automatically add resource quota that constrains whether
		// components that are marked cluster or node critical
		// can be scheduled.
		objs = append(objs, c.fluentdResourceQuota())
	}
	if c.cfg.S3Credential != nil {
		objs = append(objs, c.s3CredentialSecret())
	}
	if c.cfg.SplkCredential != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(LogCollectorNamespace, c.splunkCredentialSecret()...)...)...)
	}
	if c.cfg.Filters != nil {
		objs = append(objs, c.filtersConfigMap())
	}
	if c.cfg.EKSConfig != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		objs = append(objs,
			c.eksLogForwarderClusterRole(),
			c.eksLogForwarderClusterRoleBinding())

		objs = append(objs, c.eksLogForwarderServiceAccount(),
			c.eksLogForwarderSecret(),
			c.eksLogForwarderDeployment())
	}

	// Add in the cluster role and binding.
	objs = append(objs,
		c.fluentdClusterRole(),
		c.fluentdClusterRoleBinding(),
	)
	if c.cfg.ManagedCluster {
		objs = append(objs, c.externalLinseedRoleBinding())
	} else {
		toDelete = append(toDelete, c.externalLinseedRoleBinding())
	}

	objs = append(objs, c.fluentdServiceAccount())
	if c.cfg.PacketCapture != nil {
		objs = append(objs, c.packetCaptureApiRole(), c.packetCaptureApiRoleBinding())
	}

	objs = append(objs, c.daemonset())

	return objs, toDelete
}

func (c *fluentdComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
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
				Name:      "tigera-linseed",
				Namespace: ElasticsearchNamespace,
			},
		},
	}
}

func (c *fluentdComponent) Ready() bool {
	return true
}

func (c *fluentdComponent) fluentdResourceQuota() *corev1.ResourceQuota {
	criticalPriorityClasses := []string{NodePriorityClassName}
	return resourcequota.ResourceQuotaForPriorityClassScope(resourcequota.TigeraCriticalResourceQuotaName, LogCollectorNamespace, criticalPriorityClasses)
}

func (c *fluentdComponent) s3CredentialSecret() *corev1.Secret {
	if c.cfg.S3Credential == nil {
		return nil
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      S3FluentdSecretName,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string][]byte{
			S3KeyIdName:     c.cfg.S3Credential.KeyId,
			S3KeySecretName: c.cfg.S3Credential.KeySecret,
		},
	}
}

func (c *fluentdComponent) filtersConfigMap() *corev1.ConfigMap {
	if c.cfg.Filters == nil {
		return nil
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentdFilterConfigMapName,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string]string{
			FluentdFilterFlowName: c.cfg.Filters.Flow,
			FluentdFilterDNSName:  c.cfg.Filters.DNS,
		},
	}
}

func (c *fluentdComponent) splunkCredentialSecret() []*corev1.Secret {
	if c.cfg.SplkCredential == nil {
		return nil
	}
	return []*corev1.Secret{
		&corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      SplunkFluentdTokenSecretName,
				Namespace: LogCollectorNamespace,
			},
			Data: map[string][]byte{
				SplunkFluentdSecretTokenKey: c.cfg.SplkCredential.Token,
			},
		},
	}
}

func (c *fluentdComponent) fluentdServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.fluentdNodeName(), Namespace: LogCollectorNamespace},
	}
}

// packetCaptureApiRole creates a role in the tigera-fluentd namespace to allow pod/exec
// only from fluentd pods. This is being used by the PacketCapture API and created
// by the operator after the namespace tigera-fluentd is created.
func (c *fluentdComponent) packetCaptureApiRole() *rbacv1.Role {
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

// packetCaptureApiRoleBinding creates a role binding within the tigera-fluentd namespace between the pod/exec role
// the service account tigera-manager. This is being used by the PacketCapture API and created
// by the operator after the namespace tigera-fluentd is created
func (c *fluentdComponent) packetCaptureApiRoleBinding() *rbacv1.RoleBinding {
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

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *fluentdComponent) daemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0
	// The rationale for this setting is that while there is no need for fluentd to be available, we want to avoid
	// potentially negative consequences of an immediate roll-out on huge clusters.
	maxUnavailable := intstr.FromInt(10)

	annots := c.cfg.TrustedBundle.HashAnnotations()

	if c.cfg.FluentdKeyPair != nil {
		annots[c.cfg.FluentdKeyPair.HashAnnotationKey()] = c.cfg.FluentdKeyPair.HashAnnotationValue()
	}
	if c.cfg.S3Credential != nil {
		annots[s3CredentialHashAnnotation] = rmeta.AnnotationHash(c.cfg.S3Credential)
	}
	if c.cfg.SplkCredential != nil {
		annots[splunkCredentialHashAnnotation] = rmeta.AnnotationHash(c.cfg.SplkCredential)
	}
	if c.cfg.Filters != nil {
		annots[filterHashAnnotation] = rmeta.AnnotationHash(c.cfg.Filters)
	}
	var initContainers []corev1.Container
	if c.cfg.FluentdKeyPair != nil && c.cfg.FluentdKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.FluentdKeyPair.InitContainer(LogCollectorNamespace))
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
			ServiceAccountName:            c.fluentdNodeName(),
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.fluentdNodeName(),
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
		if overrides := c.cfg.LogCollector.Spec.FluentdDaemonSet; overrides != nil {
			rcomponents.ApplyDaemonSetOverrides(ds, overrides)
		}
	}
	setNodeCriticalPod(&(ds.Spec.Template))
	return ds
}

// container creates the fluentd container.
func (c *fluentdComponent) container() corev1.Container {
	// Determine environment to pass to the CNI init container.
	envs := c.envvars()
	volumeMounts := []corev1.VolumeMount{
		{MountPath: c.path("/var/log/calico"), Name: "var-log-calico"},
		{MountPath: c.path("/etc/fluentd/elastic"), Name: certificatemanagement.TrustedCertConfigMapName},
	}
	if c.cfg.Filters != nil {
		if c.cfg.Filters.Flow != "" {
			volumeMounts = append(volumeMounts,
				corev1.VolumeMount{
					Name:      "fluentd-filters",
					MountPath: c.path("/etc/fluentd/flow-filters.conf"),
					SubPath:   FluentdFilterFlowName,
				})
		}
		if c.cfg.Filters.DNS != "" {
			volumeMounts = append(volumeMounts,
				corev1.VolumeMount{
					Name:      "fluentd-filters",
					MountPath: c.path("/etc/fluentd/dns-filters.conf"),
					SubPath:   FluentdFilterDNSName,
				})
		}
	}

	volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)

	if c.cfg.FluentdKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.FluentdKeyPair.VolumeMount(c.SupportedOSType()))
	}

	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: c.path(LinseedVolumeMountPath),
			})
	}

	return corev1.Container{
		Name:            "fluentd",
		Image:           c.image,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             envs,
		// On OpenShift Fluentd needs privileged access to access logs on host path volume
		SecurityContext: c.securityContext(c.cfg.Installation.KubernetesProvider.IsOpenShift()),
		VolumeMounts:    volumeMounts,
		StartupProbe:    c.startup(),
		LivenessProbe:   c.liveness(),
		ReadinessProbe:  c.readiness(),
		Ports: []corev1.ContainerPort{{
			Name:          "metrics-port",
			ContainerPort: FluentdMetricsPort,
		}},
	}
}

func (c *fluentdComponent) metricsService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.fluentdMetricsServiceName(),
			Namespace: LogCollectorNamespace,
			Labels:    map[string]string{"k8s-app": c.fluentdNodeName()},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.fluentdNodeName()},
			// Important: "None" tells Kubernetes that we want a headless service with
			// no kube-proxy load balancer.  If we omit this then kube-proxy will render
			// a huge set of iptables rules for this service since there's an instance
			// on every node.
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       FluentdMetricsPortName,
					Port:       int32(FluentdMetricsPort),
					TargetPort: intstr.FromInt(FluentdMetricsPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *fluentdComponent) envvars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "LINSEED_ENABLED", Value: "true"},
		// Determine the namespace in which Linseed is running. For managed and standalone clusters, this is always the elasticsearch
		// namespace. For multi-tenant management clusters, this may vary.
		{Name: "LINSEED_ENDPOINT", Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant))},
		{Name: "LINSEED_CA_PATH", Value: c.trustedBundlePath()},
		{Name: "TLS_KEY_PATH", Value: c.keyPath()},
		{Name: "TLS_CRT_PATH", Value: c.certPath()},
		{Name: "FLUENT_UID", Value: "0"},
		{Name: "FLOW_LOG_FILE", Value: c.path("/var/log/calico/flowlogs/flows.log")},
		{Name: "DNS_LOG_FILE", Value: c.path("/var/log/calico/dnslogs/dns.log")},
		{Name: "FLUENTD_ES_SECURE", Value: "true"},
		{Name: "NODENAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
		{Name: "LINSEED_TOKEN", Value: c.path(GetLinseedTokenPath(c.cfg.ManagedCluster))},
	}

	if c.cfg.Tenant != nil && c.cfg.ExternalElastic {
		envs = append(envs, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
	}

	if c.cfg.LogCollector.Spec.AdditionalStores != nil {
		s3 := c.cfg.LogCollector.Spec.AdditionalStores.S3
		if s3 != nil {
			envs = append(envs,
				corev1.EnvVar{
					Name: "AWS_KEY_ID",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: S3FluentdSecretName,
							},
							Key: S3KeyIdName,
						},
					},
				},
				corev1.EnvVar{
					Name: "AWS_SECRET_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: S3FluentdSecretName,
							},
							Key: S3KeySecretName,
						},
					},
				},
				corev1.EnvVar{Name: "S3_STORAGE", Value: "true"},
				corev1.EnvVar{Name: "S3_BUCKET_NAME", Value: s3.BucketName},
				corev1.EnvVar{Name: "AWS_REGION", Value: s3.Region},
				corev1.EnvVar{Name: "S3_BUCKET_PATH", Value: s3.BucketPath},
				corev1.EnvVar{Name: "S3_FLUSH_INTERVAL", Value: fluentdDefaultFlush},
			)
		}
		syslog := c.cfg.LogCollector.Spec.AdditionalStores.Syslog
		if syslog != nil {
			proto, host, port, _ := url.ParseEndpoint(syslog.Endpoint)
			envs = append(envs,
				corev1.EnvVar{Name: "SYSLOG_HOST", Value: host},
				corev1.EnvVar{Name: "SYSLOG_PORT", Value: port},
				corev1.EnvVar{Name: "SYSLOG_PROTOCOL", Value: proto},
				corev1.EnvVar{Name: "SYSLOG_FLUSH_INTERVAL", Value: fluentdDefaultFlush},
				corev1.EnvVar{
					Name: "SYSLOG_HOSTNAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "spec.nodeName",
						},
					},
				},
			)
			if syslog.PacketSize != nil {
				envs = append(envs,
					corev1.EnvVar{
						Name:  "SYSLOG_PACKET_SIZE",
						Value: fmt.Sprintf("%d", *syslog.PacketSize),
					},
				)
			}

			if syslog.LogTypes != nil {
				for _, t := range syslog.LogTypes {
					switch t {
					case operatorv1.SyslogLogAudit:
						envs = append(envs,
							corev1.EnvVar{Name: "SYSLOG_AUDIT_EE_LOG", Value: "true"},
						)
						envs = append(envs,
							corev1.EnvVar{Name: "SYSLOG_AUDIT_KUBE_LOG", Value: "true"},
						)
					case operatorv1.SyslogLogDNS:
						envs = append(envs,
							corev1.EnvVar{Name: "SYSLOG_DNS_LOG", Value: "true"},
						)
					case operatorv1.SyslogLogFlows:
						envs = append(envs,
							corev1.EnvVar{Name: "SYSLOG_FLOW_LOG", Value: "true"},
						)
					case operatorv1.SyslogLogIDSEvents:
						envs = append(envs,
							corev1.EnvVar{Name: "SYSLOG_IDS_EVENT_LOG", Value: "true"},
						)
					}
				}
			}

			if syslog.Encryption == operatorv1.EncryptionTLS {
				envs = append(envs,
					corev1.EnvVar{Name: "SYSLOG_TLS", Value: "true"},
				)
				// By default, we would be using the secure verification mode OpenSSL::SSL::VERIFY_PEER(1)
				envs = append(envs,
					corev1.EnvVar{Name: "SYSLOG_VERIFY_MODE", Value: "1"},
				)
				if c.cfg.UseSyslogCertificate {
					envs = append(envs,
						corev1.EnvVar{Name: "SYSLOG_CA_FILE", Value: c.cfg.TrustedBundle.MountPath()},
					)
				} else {
					envs = append(envs,
						corev1.EnvVar{Name: "SYSLOG_CA_FILE", Value: SysLogPublicCAPath},
					)
				}
			}
		}
		splunk := c.cfg.LogCollector.Spec.AdditionalStores.Splunk
		if splunk != nil {
			proto, host, port, _ := url.ParseEndpoint(splunk.Endpoint)
			envs = append(envs,
				corev1.EnvVar{
					Name: "SPLUNK_HEC_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: SplunkFluentdTokenSecretName,
							},
							Key: SplunkFluentdSecretTokenKey,
						},
					},
				},
				corev1.EnvVar{Name: "SPLUNK_FLOW_LOG", Value: "true"},
				corev1.EnvVar{Name: "SPLUNK_AUDIT_LOG", Value: "true"},
				corev1.EnvVar{Name: "SPLUNK_DNS_LOG", Value: "true"},
				corev1.EnvVar{Name: "SPLUNK_HEC_HOST", Value: host},
				corev1.EnvVar{Name: "SPLUNK_HEC_PORT", Value: port},
				corev1.EnvVar{Name: "SPLUNK_PROTOCOL", Value: proto},
				corev1.EnvVar{Name: "SPLUNK_FLUSH_INTERVAL", Value: fluentdDefaultFlush},
			)
		}
	}

	if c.cfg.Filters != nil {
		if c.cfg.Filters.Flow != "" {
			envs = append(envs,
				corev1.EnvVar{Name: "FLUENTD_FLOW_FILTERS", Value: "true"})
		}
		if c.cfg.Filters.DNS != "" {
			envs = append(envs,
				corev1.EnvVar{Name: "FLUENTD_DNS_FILTERS", Value: "true"})
		}
	}

	envs = append(envs, corev1.EnvVar{Name: "CA_CRT_PATH", Value: c.trustedBundlePath()})

	return envs
}

func (c *fluentdComponent) trustedBundlePath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return certificatemanagement.TrustedCertBundleMountPathWindows
	}
	return c.cfg.TrustedBundle.MountPath()
}

func (c *fluentdComponent) keyPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentdKeyPair.GetName(), corev1.TLSPrivateKeyKey)
	}
	return c.cfg.FluentdKeyPair.VolumeMountKeyFilePath()
}

func (c *fluentdComponent) certPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentdKeyPair.GetName(), corev1.TLSCertKey)
	}
	return c.cfg.FluentdKeyPair.VolumeMountCertificateFilePath()
}

// The startup probe uses the same action as the liveness probe, but with
// a higher failure threshold and double the timeout to account for slow
// networks.
func (c *fluentdComponent) startup() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: c.livenessCmd(),
			},
		},
		TimeoutSeconds: c.probeTimeout,
		PeriodSeconds:  c.probePeriod,
		// tolerate more failures for the startup probe
		FailureThreshold: 10,
	}
}

func (c *fluentdComponent) liveness() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: c.livenessCmd(),
			},
		},
		TimeoutSeconds: c.probeTimeout,
		PeriodSeconds:  c.probePeriod,
	}
}

func (c *fluentdComponent) readiness() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: c.readinessCmd(),
			},
		},
		TimeoutSeconds: c.probeTimeout,
		PeriodSeconds:  c.probePeriod,
	}
}

func (c *fluentdComponent) volumes() []corev1.Volume {
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
	}
	if c.cfg.Filters != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name: "fluentd-filters",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: FluentdFilterConfigMapName,
						},
					},
				},
			})
	}
	if c.cfg.FluentdKeyPair != nil {
		volumes = append(volumes, c.cfg.FluentdKeyPair.Volume())
	}
	if c.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, FluentdNodeName),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
	}
	volumes = append(volumes, trustedBundleVolume(c.cfg.TrustedBundle))

	return volumes
}

func (c *fluentdComponent) fluentdClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.fluentdName(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     c.fluentdName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      c.fluentdNodeName(),
				Namespace: LogCollectorNamespace,
			},
		},
	}
}

func (c *fluentdComponent) fluentdClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.fluentdName(),
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

func (c *fluentdComponent) eksLogForwarderServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: EKSLogForwarderName, Namespace: LogCollectorNamespace},
	}
}

func (c *fluentdComponent) eksLogForwarderSecret() *corev1.Secret {
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

func (c *fluentdComponent) eksLogForwarderDeployment() *appsv1.Deployment {
	annots := map[string]string{
		eksCloudwatchLogCredentialHashAnnotation: rmeta.AnnotationHash(c.cfg.EKSConfig),
	}

	envVars := []corev1.EnvVar{
		// Meta flags.
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "FLUENT_UID", Value: "0"},
		// Use fluentd for EKS log forwarder.
		{Name: "MANAGED_K8S", Value: "true"},
		{Name: "K8S_PLATFORM", Value: "eks"},
		{Name: "FLUENTD_ES_SECURE", Value: "true"},
		// Cloudwatch config, credentials.
		{Name: "EKS_CLOUDWATCH_LOG_GROUP", Value: c.cfg.EKSConfig.GroupName},
		{Name: "EKS_CLOUDWATCH_LOG_STREAM_PREFIX", Value: c.cfg.EKSConfig.StreamPrefix},
		{Name: "EKS_CLOUDWATCH_LOG_FETCH_INTERVAL", Value: fmt.Sprintf("%d", c.cfg.EKSConfig.FetchInterval)},
		{Name: "AWS_REGION", Value: c.cfg.EKSConfig.AwsRegion},
		{Name: "AWS_ACCESS_KEY_ID", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsId, false)},
		{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsKey, false)},
		{Name: "LINSEED_ENABLED", Value: "true"},
		// Determine the namespace in which Linseed is running. For managed and standalone clusters, this is always the elasticsearch
		// namespace. For multi-tenant management clusters, this may vary.
		{Name: "LINSEED_ENDPOINT", Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant))},
		{Name: "LINSEED_CA_PATH", Value: c.trustedBundlePath()},
		{Name: "TLS_CRT_PATH", Value: c.cfg.EKSLogForwarderKeyPair.VolumeMountCertificateFilePath()},
		{Name: "TLS_KEY_PATH", Value: c.cfg.EKSLogForwarderKeyPair.VolumeMountKeyFilePath()},
		{Name: "LINSEED_TOKEN", Value: c.path(GetLinseedTokenPath(c.cfg.ManagedCluster))},
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
					InitContainers: []corev1.Container{{
						Name:            EKSLogForwarderName + "-startup",
						Image:           c.image,
						ImagePullPolicy: ImagePullPolicy(),
						Command:         []string{c.path("/bin/eks-log-forwarder-startup")},
						Env:             envVars,
						SecurityContext: c.securityContext(false),
						VolumeMounts:    c.eksLogForwarderVolumeMounts(),
					}},
					Containers: []corev1.Container{{
						Name:            EKSLogForwarderName,
						Image:           c.image,
						ImagePullPolicy: ImagePullPolicy(),
						Env:             envVars,
						SecurityContext: c.securityContext(false),
						VolumeMounts:    c.eksLogForwarderVolumeMounts(),
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
		{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: SplunkFluentdSecretCertificateKey},
		{Key: certificatemanagement.RHELRootCertificateBundleName, Path: certificatemanagement.RHELRootCertificateBundleName},
	}
	return volume
}

func (c *fluentdComponent) eksLogForwarderVolumeMounts() []corev1.VolumeMount {

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "plugin-statefile-dir",
			MountPath: c.path("/fluentd/cloudwatch-logs/"),
		},
		{
			Name:      certificatemanagement.TrustedCertConfigMapName,
			MountPath: c.path("/etc/fluentd/elastic/"),
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

func (c *fluentdComponent) eksLogForwarderVolumes() []corev1.Volume {

	volumes := []corev1.Volume{
		trustedBundleVolume(c.cfg.TrustedBundle),
		{
			Name: "plugin-statefile-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: nil,
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

func (c *fluentdComponent) eksLogForwarderClusterRoleBinding() *rbacv1.ClusterRoleBinding {
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

func (c *fluentdComponent) eksLogForwarderClusterRole() *rbacv1.ClusterRole {
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

func (c *fluentdComponent) allowTigeraPolicy() *v3.NetworkPolicy {
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

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentdPolicyName,
			Namespace: LogCollectorNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:                  &networkpolicy.HighPrecedenceOrder,
			Tier:                   networkpolicy.TigeraComponentTierName,
			Selector:               networkpolicy.KubernetesAppSelector(FluentdNodeName, fluentdNodeWindowsName),
			ServiceAccountSelector: "",
			Types:                  []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   networkpolicy.PrometheusSourceEntityRule,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(FluentdMetricsPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}
