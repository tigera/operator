// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strconv"

	"github.com/tigera/operator/pkg/url"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	LogCollectorNamespace                    = "tigera-fluentd"
	FluentdFilterConfigMapName               = "fluentd-filters"
	FluentdFilterFlowName                    = "flow"
	FluentdFilterDNSName                     = "dns"
	S3FluentdSecretName                      = "log-collector-s3-credentials"
	S3KeyIdName                              = "key-id"
	S3KeySecretName                          = "key-secret"
	filterHashAnnotation                     = "hash.operator.tigera.io/fluentd-filters"
	s3CredentialHashAnnotation               = "hash.operator.tigera.io/s3-credentials"
	splunkCredentialHashAnnotation           = "hash.operator.tigera.io/splunk-credentials"
	eksCloudwatchLogCredentialHashAnnotation = "hash.operator.tigera.io/eks-cloudwatch-log-credentials"
	fluentdDefaultFlush                      = "5s"
	ElasticsearchLogCollectorUserSecret      = "tigera-fluentd-elasticsearch-access"
	ElasticsearchEksLogForwarderUserSecret   = "tigera-eks-log-forwarder-elasticsearch-access"
	EksLogForwarderSecret                    = "tigera-eks-log-forwarder-secret"
	EksLogForwarderAwsId                     = "aws-id"
	EksLogForwarderAwsKey                    = "aws-key"
	SplunkFluentdTokenSecretName             = "logcollector-splunk-credentials"
	SplunkFluentdSecretTokenKey              = "token"
	SplunkFluentdCertificateSecretName       = "logcollector-splunk-public-certificate"
	SplunkFluentdSecretCertificateKey        = "ca.pem"
	SplunkFluentdSecretsVolName              = "splunk-certificates"
	SplunkFluentdDefaultCertDir              = "/etc/ssl/splunk/"
	SplunkFluentdDefaultCertPath             = SplunkFluentdDefaultCertDir + SplunkFluentdSecretCertificateKey

	ProbeTimeoutSeconds = 5
	ProbePeriodSeconds  = 10

	fluentdName        = "tigera-fluentd"
	fluentdWindowsName = "tigera-fluentd-windows"

	fluentdNodeName        = "fluentd-node"
	fluentdNodeWindowsName = "fluentd-node-windows"

	eksLogForwarderName        = "eks-log-forwarder"
	eksLogForwarderWindowsName = "eks-log-forwarder-windows"
)

type FluentdFilters struct {
	Flow string
	DNS  string
}

type S3Credential struct {
	KeyId     []byte
	KeySecret []byte
}

type SplunkCredential struct {
	Token       []byte
	Certificate []byte
}

func Fluentd(
	lc *operatorv1.LogCollector,
	esSecrets []*corev1.Secret,
	esClusterConfig *relasticsearch.ClusterConfig,
	s3C *S3Credential,
	spC *SplunkCredential,
	f *FluentdFilters,
	eksConfig *EksCloudwatchLogConfig,
	pullSecrets []*corev1.Secret,
	installation *operatorv1.InstallationSpec,
	clusterDomain string,
	osType rmeta.OSType,
	exportLogsToAdditionalStorages bool,
) Component {
	return &fluentdComponent{
		lc:                             lc,
		esSecrets:                      esSecrets,
		esClusterConfig:                esClusterConfig,
		s3Credential:                   s3C,
		splkCredential:                 spC,
		filters:                        f,
		eksConfig:                      eksConfig,
		pullSecrets:                    pullSecrets,
		installation:                   installation,
		clusterDomain:                  clusterDomain,
		osType:                         osType,
		exportLogsToAdditionalStorages: exportLogsToAdditionalStorages,
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

type fluentdComponent struct {
	lc                             *operatorv1.LogCollector
	esSecrets                      []*corev1.Secret
	esClusterConfig                *relasticsearch.ClusterConfig
	s3Credential                   *S3Credential
	splkCredential                 *SplunkCredential
	filters                        *FluentdFilters
	eksConfig                      *EksCloudwatchLogConfig
	pullSecrets                    []*corev1.Secret
	installation                   *operatorv1.InstallationSpec
	clusterDomain                  string
	osType                         rmeta.OSType
	image                          string
	exportLogsToAdditionalStorages bool
}

func (c *fluentdComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.installation.Registry
	path := c.installation.ImagePath

	if c.osType == rmeta.OSTypeWindows {
		var err error
		c.image, err = components.GetReference(components.ComponentFluentdWindows, reg, path, is)
		return err
	}

	var err error
	c.image, err = components.GetReference(components.ComponentFluentd, reg, path, is)
	return err
}

func (c *fluentdComponent) SupportedOSType() rmeta.OSType {
	return c.osType
}

func (c *fluentdComponent) fluentdName() string {
	if c.osType == rmeta.OSTypeWindows {
		return fluentdWindowsName
	}
	return fluentdName
}

func (c *fluentdComponent) fluentdNodeName() string {
	if c.osType == rmeta.OSTypeWindows {
		return fluentdNodeWindowsName
	}
	return fluentdNodeName
}

func (c *fluentdComponent) eksLogForwarderName() string {
	if c.osType == rmeta.OSTypeWindows {
		return eksLogForwarderWindowsName
	}
	return eksLogForwarderName
}

func (c *fluentdComponent) readinessCmd() []string {
	if c.osType == rmeta.OSTypeWindows {
		// On Windows, we rely on bash via msys2 installed by the fluentd base image.
		return []string{`c:\ruby26\msys64\usr\bin\bash.exe`, `-lc`, `/c/bin/readiness.sh`}
	}
	return []string{"sh", "-c", "/bin/readiness.sh"}
}

func (c *fluentdComponent) livenessCmd() []string {
	if c.osType == rmeta.OSTypeWindows {
		// On Windows, we rely on bash via msys2 installed by the fluentd base image.
		return []string{`c:\ruby26\msys64\usr\bin\bash.exe`, `-lc`, `/c/bin/liveness.sh`}
	}
	return []string{"sh", "-c", "/bin/liveness.sh"}
}

func (c *fluentdComponent) volumeHostPath() string {
	if c.osType == rmeta.OSTypeWindows {
		return "c:/TigeraCalico"
	}
	return "/var/log/calico"
}

func (c *fluentdComponent) path(path string) string {
	if c.osType == rmeta.OSTypeWindows {
		// Use c: path prefix for windows.
		return "c:" + path
	}
	// For linux just leave the path as-is.
	return path
}

func (c *fluentdComponent) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object
	objs = append(objs,
		createNamespace(
			LogCollectorNamespace,
			c.installation.KubernetesProvider))
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(LogCollectorNamespace, c.pullSecrets...)...)...)
	if c.s3Credential != nil {
		objs = append(objs, c.s3CredentialSecret())
	}
	if c.splkCredential != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(LogCollectorNamespace, c.splunkCredentialSecret()...)...)...)
	}
	if c.filters != nil {
		objs = append(objs, c.filtersConfigMap())
	}
	if c.eksConfig != nil {
		// Windows PSP does not support allowedHostPaths yet.
		// See: https://github.com/kubernetes/kubernetes/issues/93165#issuecomment-693049808
		if c.installation.KubernetesProvider != operatorv1.ProviderOpenShift && c.osType == rmeta.OSTypeLinux {
			objs = append(objs,
				c.eksLogForwarderClusterRole(),
				c.eksLogForwarderClusterRoleBinding(),
				c.eksLogForwarderPodSecurityPolicy())
		}
		objs = append(objs, c.eksLogForwarderServiceAccount(),
			c.eksLogForwarderSecret(),
			c.eksLogForwarderDeployment())
	}

	// Windows PSP does not support allowedHostPaths yet.
	// See: https://github.com/kubernetes/kubernetes/issues/93165#issuecomment-693049808
	if c.installation.KubernetesProvider != operatorv1.ProviderOpenShift && c.osType == rmeta.OSTypeLinux {
		objs = append(objs,
			c.fluentdClusterRole(),
			c.fluentdClusterRoleBinding(),
			c.fluentdPodSecurityPolicy())
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(LogCollectorNamespace, c.esSecrets...)...)...)
	objs = append(objs, c.fluentdServiceAccount())
	objs = append(objs, c.daemonset())

	return objs, nil
}

func (c *fluentdComponent) Ready() bool {
	return true
}

func (c *fluentdComponent) s3CredentialSecret() *corev1.Secret {
	if c.s3Credential == nil {
		return nil
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      S3FluentdSecretName,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string][]byte{
			S3KeyIdName:     c.s3Credential.KeyId,
			S3KeySecretName: c.s3Credential.KeySecret,
		},
	}
}

func (c *fluentdComponent) filtersConfigMap() *corev1.ConfigMap {
	if c.filters == nil {
		return nil
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentdFilterConfigMapName,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string]string{
			FluentdFilterFlowName: c.filters.Flow,
			FluentdFilterDNSName:  c.filters.DNS,
		},
	}
}

func (c *fluentdComponent) splunkCredentialSecret() []*corev1.Secret {
	if c.splkCredential == nil {
		return nil
	}
	var splunkSecrets []*corev1.Secret
	token := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      SplunkFluentdTokenSecretName,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string][]byte{
			SplunkFluentdSecretTokenKey: c.splkCredential.Token,
		},
	}

	splunkSecrets = append(splunkSecrets, token)

	if len(c.splkCredential.Certificate) != 0 {
		certificate := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      SplunkFluentdCertificateSecretName,
				Namespace: LogCollectorNamespace,
			},
			Data: map[string][]byte{
				SplunkFluentdSecretCertificateKey: c.splkCredential.Certificate,
			},
		}
		splunkSecrets = append(splunkSecrets, certificate)
	}

	return splunkSecrets
}

func (c *fluentdComponent) fluentdServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.fluentdNodeName(), Namespace: LogCollectorNamespace},
	}
}

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *fluentdComponent) daemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0
	maxUnavailable := intstr.FromInt(1)

	annots := map[string]string{}
	if c.s3Credential != nil {
		annots[s3CredentialHashAnnotation] = rmeta.AnnotationHash(c.s3Credential)
	}
	if c.splkCredential != nil {
		annots[splunkCredentialHashAnnotation] = rmeta.AnnotationHash(c.splkCredential)
	}
	if c.filters != nil {
		annots[filterHashAnnotation] = rmeta.AnnotationHash(c.filters)
	}

	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"k8s-app": c.fluentdNodeName(),
			},
			Annotations: annots,
		},
		Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
			NodeSelector:                  map[string]string{},
			Tolerations:                   c.tolerations(),
			ImagePullSecrets:              secret.GetReferenceList(c.pullSecrets),
			TerminationGracePeriodSeconds: &terminationGracePeriod,
			Containers:                    []corev1.Container{c.container()},
			Volumes:                       c.volumes(),
			ServiceAccountName:            c.fluentdNodeName(),
		}),
	}, c.esClusterConfig, c.esSecrets).(*corev1.PodTemplateSpec)

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.fluentdNodeName(),
			Namespace: LogCollectorNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": c.fluentdNodeName()}},
			Template: *podTemplate,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}

	setCriticalPod(&(ds.Spec.Template))
	return ds
}

// logCollectorTolerations creates the node's tolerations.
func (c *fluentdComponent) tolerations() []corev1.Toleration {
	tolerations := []corev1.Toleration{
		{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
	}

	return tolerations
}

// container creates the fluentd container.
func (c *fluentdComponent) container() corev1.Container {
	// Determine environment to pass to the CNI init container.
	envs := c.envvars()
	volumeMounts := []corev1.VolumeMount{
		{MountPath: c.path("/var/log/calico"), Name: "var-log-calico"},
		{MountPath: c.path("/etc/fluentd/elastic"), Name: "elastic-ca-cert-volume"},
	}
	if c.filters != nil {
		if c.filters.Flow != "" {
			volumeMounts = append(volumeMounts,
				corev1.VolumeMount{
					Name:      "fluentd-filters",
					MountPath: c.path("/etc/fluentd/flow-filters.conf"),
					SubPath:   FluentdFilterFlowName,
				})
		}
		if c.filters.DNS != "" {
			volumeMounts = append(volumeMounts,
				corev1.VolumeMount{
					Name:      "fluentd-filters",
					MountPath: c.path("/etc/fluentd/dns-filters.conf"),
					SubPath:   FluentdFilterDNSName,
				})
		}
	}

	if c.splkCredential != nil && len(c.splkCredential.Certificate) != 0 {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      SplunkFluentdSecretsVolName,
				MountPath: SplunkFluentdDefaultCertDir,
			})
	}

	isPrivileged := false
	//On OpenShift Fluentd needs privileged access to access logs on host path volume
	if c.installation.KubernetesProvider == operatorv1.ProviderOpenShift {
		isPrivileged = true
	}

	return relasticsearch.ContainerDecorateENVVars(corev1.Container{
		Name:            "fluentd",
		Image:           c.image,
		Env:             envs,
		SecurityContext: &corev1.SecurityContext{Privileged: &isPrivileged},
		VolumeMounts:    volumeMounts,
		StartupProbe:    c.startup(),
		LivenessProbe:   c.liveness(),
		ReadinessProbe:  c.readiness(),
	}, c.esClusterConfig.ClusterName(), ElasticsearchLogCollectorUserSecret, c.clusterDomain, c.osType)
}

func (c *fluentdComponent) envvars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "FLUENT_UID", Value: "0"},
		{Name: "FLOW_LOG_FILE", Value: c.path("/var/log/calico/flowlogs/flows.log")},
		{Name: "DNS_LOG_FILE", Value: c.path("/var/log/calico/dnslogs/dns.log")},
		{Name: "FLUENTD_ES_SECURE", Value: "true"},
		{Name: "NODENAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
	}

	if c.exportLogsToAdditionalStorages && c.lc.Spec.AdditionalStores != nil {
		s3 := c.lc.Spec.AdditionalStores.S3
		if s3 != nil {
			envs = append(envs,
				corev1.EnvVar{Name: "AWS_KEY_ID",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: S3FluentdSecretName,
							},
							Key: S3KeyIdName,
						},
					}},
				corev1.EnvVar{Name: "AWS_SECRET_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: S3FluentdSecretName,
							},
							Key: S3KeySecretName,
						},
					}},
				corev1.EnvVar{Name: "S3_STORAGE", Value: "true"},
				corev1.EnvVar{Name: "S3_BUCKET_NAME", Value: s3.BucketName},
				corev1.EnvVar{Name: "AWS_REGION", Value: s3.Region},
				corev1.EnvVar{Name: "S3_BUCKET_PATH", Value: s3.BucketPath},
				corev1.EnvVar{Name: "S3_FLUSH_INTERVAL", Value: fluentdDefaultFlush},
			)
		}
		syslog := c.lc.Spec.AdditionalStores.Syslog
		if c.exportLogsToAdditionalStorages && syslog != nil {
			proto, host, port, _ := url.ParseEndpoint(syslog.Endpoint)
			envs = append(envs,
				corev1.EnvVar{Name: "SYSLOG_HOST", Value: host},
				corev1.EnvVar{Name: "SYSLOG_PORT", Value: port},
				corev1.EnvVar{Name: "SYSLOG_PROTOCOL", Value: proto},
				corev1.EnvVar{Name: "SYSLOG_FLUSH_INTERVAL", Value: fluentdDefaultFlush},
				corev1.EnvVar{Name: "SYSLOG_HOSTNAME",
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
		}
		splunk := c.lc.Spec.AdditionalStores.Splunk
		if c.exportLogsToAdditionalStorages && splunk != nil {
			proto, host, port, _ := url.ParseEndpoint(splunk.Endpoint)
			envs = append(envs,
				corev1.EnvVar{Name: "SPLUNK_HEC_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: SplunkFluentdTokenSecretName,
							},
							Key: SplunkFluentdSecretTokenKey,
						},
					}},
				corev1.EnvVar{Name: "SPLUNK_FLOW_LOG", Value: "true"},
				corev1.EnvVar{Name: "SPLUNK_AUDIT_LOG", Value: "true"},
				corev1.EnvVar{Name: "SPLUNK_DNS_LOG", Value: "true"},
				corev1.EnvVar{Name: "SPLUNK_HEC_HOST", Value: host},
				corev1.EnvVar{Name: "SPLUNK_HEC_PORT", Value: port},
				corev1.EnvVar{Name: "SPLUNK_PROTOCOL", Value: proto},
				corev1.EnvVar{Name: "SPLUNK_FLUSH_INTERVAL", Value: fluentdDefaultFlush},
			)
			if len(c.splkCredential.Certificate) != 0 {
				envs = append(envs,
					corev1.EnvVar{Name: "SPLUNK_CA_FILE", Value: SplunkFluentdDefaultCertPath},
				)
			}
		}
	}

	if c.filters != nil {
		if c.filters.Flow != "" {
			envs = append(envs,
				corev1.EnvVar{Name: "FLUENTD_FLOW_FILTERS", Value: "true"})
		}
		if c.filters.DNS != "" {
			envs = append(envs,
				corev1.EnvVar{Name: "FLUENTD_DNS_FILTERS", Value: "true"})
		}
	}

	envs = append(envs,
		corev1.EnvVar{Name: "ELASTIC_FLOWS_INDEX_REPLICAS", Value: strconv.Itoa(c.esClusterConfig.Replicas())},
		corev1.EnvVar{Name: "ELASTIC_DNS_INDEX_REPLICAS", Value: strconv.Itoa(c.esClusterConfig.Replicas())},
		corev1.EnvVar{Name: "ELASTIC_AUDIT_INDEX_REPLICAS", Value: strconv.Itoa(c.esClusterConfig.Replicas())},
		corev1.EnvVar{Name: "ELASTIC_BGP_INDEX_REPLICAS", Value: strconv.Itoa(c.esClusterConfig.Replicas())},

		corev1.EnvVar{Name: "ELASTIC_FLOWS_INDEX_SHARDS", Value: strconv.Itoa(c.esClusterConfig.FlowShards())},
		corev1.EnvVar{Name: "ELASTIC_DNS_INDEX_SHARDS", Value: strconv.Itoa(c.esClusterConfig.Shards())},
		corev1.EnvVar{Name: "ELASTIC_AUDIT_INDEX_SHARDS", Value: strconv.Itoa(c.esClusterConfig.Shards())},
		corev1.EnvVar{Name: "ELASTIC_BGP_INDEX_SHARDS", Value: strconv.Itoa(c.esClusterConfig.Shards())},
	)

	return envs
}

// The startup probe uses the same action as the liveness probe, but with
// a higher failure threshold and a larger timeout to account for slow networks.
func (c *fluentdComponent) startup() *corev1.Probe {
	// Default failure threshold for probes is 3. For the startup we should
	// tolerate more failures.
	var startupProbeFailureThreshold int32 = 10

	return &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: c.livenessCmd(),
			},
		},
		TimeoutSeconds:   ProbeTimeoutSeconds * 2,
		PeriodSeconds:    ProbePeriodSeconds,
		FailureThreshold: startupProbeFailureThreshold,
	}
}

func (c *fluentdComponent) liveness() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: c.livenessCmd(),
			},
		},
		TimeoutSeconds: ProbeTimeoutSeconds,
		PeriodSeconds:  ProbePeriodSeconds,
	}
}

func (c *fluentdComponent) readiness() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: c.readinessCmd(),
			},
		},
		TimeoutSeconds: ProbeTimeoutSeconds,
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
	if c.filters != nil {
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

	if c.splkCredential != nil && len(c.splkCredential.Certificate) != 0 {
		volumes = append(volumes,
			corev1.Volume{
				Name: SplunkFluentdSecretsVolName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: SplunkFluentdCertificateSecretName,
						Items: []corev1.KeyToPath{
							{Key: SplunkFluentdSecretCertificateKey, Path: SplunkFluentdSecretCertificateKey},
						},
					},
				},
			})
	}

	return volumes
}

func (c *fluentdComponent) fluentdPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(c.fluentdName())
	psp.Spec.RequiredDropCapabilities = nil
	psp.Spec.AllowedCapabilities = []corev1.Capability{
		corev1.Capability("CAP_CHOWN"),
	}
	psp.Spec.Volumes = append(psp.Spec.Volumes, policyv1beta1.HostPath)
	psp.Spec.AllowedHostPaths = []policyv1beta1.AllowedHostPath{
		{
			PathPrefix: c.path("/var/log/calico"),
			ReadOnly:   false,
		},
	}
	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny
	return psp
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
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.fluentdName(),
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{c.fluentdName()},
			},
		},
	}
}

func (c *fluentdComponent) eksLogForwarderServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.eksLogForwarderName(), Namespace: LogCollectorNamespace},
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
			EksLogForwarderAwsId:  c.eksConfig.AwsId,
			EksLogForwarderAwsKey: c.eksConfig.AwsKey,
		},
	}
}

func (c *fluentdComponent) eksLogForwarderDeployment() *appsv1.Deployment {
	annots := map[string]string{
		eksCloudwatchLogCredentialHashAnnotation: rmeta.AnnotationHash(c.eksConfig),
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
		{Name: "EKS_CLOUDWATCH_LOG_GROUP", Value: c.eksConfig.GroupName},
		{Name: "EKS_CLOUDWATCH_LOG_STREAM_PREFIX", Value: c.eksConfig.StreamPrefix},
		{Name: "EKS_CLOUDWATCH_LOG_FETCH_INTERVAL", Value: fmt.Sprintf("%d", c.eksConfig.FetchInterval)},
		{Name: "AWS_REGION", Value: c.eksConfig.AwsRegion},
		{Name: "AWS_ACCESS_KEY_ID", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsId, false)},
		{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsKey, false)},
	}

	var eksLogForwarderReplicas int32 = 1

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.eksLogForwarderName(),
			Namespace: LogCollectorNamespace,
			Labels: map[string]string{
				"k8s-app": c.eksLogForwarderName(),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &eksLogForwarderReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": c.eksLogForwarderName(),
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      c.eksLogForwarderName(),
					Namespace: LogCollectorNamespace,
					Labels: map[string]string{
						"k8s-app": c.eksLogForwarderName(),
					},
					Annotations: annots,
				},
				Spec: corev1.PodSpec{
					Tolerations:        c.installation.ControlPlaneTolerations,
					ServiceAccountName: c.eksLogForwarderName(),
					ImagePullSecrets:   secret.GetReferenceList(c.pullSecrets),
					InitContainers: []corev1.Container{relasticsearch.ContainerDecorateENVVars(corev1.Container{
						Name:         c.eksLogForwarderName() + "-startup",
						Image:        c.image,
						Command:      []string{c.path("/bin/eks-log-forwarder-startup")},
						Env:          envVars,
						VolumeMounts: c.eksLogForwarderVolumeMounts(),
					}, c.esClusterConfig.ClusterName(), ElasticsearchEksLogForwarderUserSecret, c.clusterDomain, c.osType)},
					Containers: []corev1.Container{relasticsearch.ContainerDecorateENVVars(corev1.Container{
						Name:         c.eksLogForwarderName(),
						Image:        c.image,
						Env:          envVars,
						VolumeMounts: c.eksLogForwarderVolumeMounts(),
					}, c.esClusterConfig.ClusterName(), ElasticsearchEksLogForwarderUserSecret, c.clusterDomain, c.osType)},
					Volumes: c.eksLogForwarderVolumes(),
				},
			},
		},
	}
}

func (c *fluentdComponent) eksLogForwarderVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		relasticsearch.DefaultVolumeMount(c.osType),
		{
			Name:      "plugin-statefile-dir",
			MountPath: c.path("/fluentd/cloudwatch-logs/"),
		},
		{
			Name:      "elastic-ca-cert-volume",
			MountPath: c.path("/etc/fluentd/elastic/"),
		},
	}
}

func (c *fluentdComponent) eksLogForwarderVolumes() []corev1.Volume {
	return []corev1.Volume{
		relasticsearch.DefaultVolume(),
		{
			Name: "plugin-statefile-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: nil,
			},
		},
	}
}

func (c *fluentdComponent) eksLogForwarderPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(c.eksLogForwarderName())
	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny
	return psp
}

func (c *fluentdComponent) eksLogForwarderClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.eksLogForwarderName(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     c.eksLogForwarderName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      c.eksLogForwarderName(),
				Namespace: LogCollectorNamespace,
			},
		},
	}
}

func (c *fluentdComponent) eksLogForwarderClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.eksLogForwarderName(),
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{c.eksLogForwarderName()},
			},
		},
	}
}
