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

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	LogCollectorNamespace                    = "tigera-fluentd"
	FluentdFilterConfigMapName               = "fluentd-filters"
	FluentdFilterFlowName                    = "flow"
	FluentdFilterDNSName                     = "dns"
	S3FluentdSecretName                      = "log-collector-s3-credentials"
	S3KeyIdName                              = "key-id"
	S3KeySecretName                          = "key-secret"
	logStorageHashAnnotation                 = "hash.operator.tigera.io/log-storage"
	elasticsearchSecretsAnnotation           = "hash.operator.tigera.io/elasticsearch-secrets"
	filterHashAnnotation                     = "hash.operator.tigera.io/fluentd-filters"
	s3CredentialHashAnnotation               = "hash.operator.tigera.io/s3-credentials"
	eksCloudwatchLogCredentialHashAnnotation = "hash.operator.tigera.io/eks-cloudwatch-log-credentials"
	fluentdDefaultFlush                      = "5s"
	ElasticsearchUserLogCollector            = "tigera-fluentd"
	ElasticsearchUserEksLogForwarder         = "tigera-eks-log-forwarder"
	EksLogForwarderSecret                    = "tigera-eks-log-forwarder-secret"
	EksLogForwarderAwsId                     = "aws-id"
	EksLogForwarderAwsKey                    = "aws-key"
	eksLogForwarderName                      = "eks-log-forwarder"
)

type FluentdFilters struct {
	Flow string
	DNS  string
}

type S3Credential struct {
	KeyId     []byte
	KeySecret []byte
}

func Fluentd(
	lc *operatorv1.LogCollector,
	ls *operatorv1.LogStorage,
	esSecrets []*corev1.Secret,
	cluster string,
	s3C *S3Credential,
	f *FluentdFilters,
	eksConfig *EksCloudwatchLogConfig,

	pullSecrets []*corev1.Secret,
	installation *operatorv1.Installation,
) Component {
	return &fluentdComponent{
		lc:           lc,
		ls:           ls,
		esSecrets:    esSecrets,
		cluster:      cluster,
		s3Credential: s3C,
		filters:      f,
		eksConfig:    eksConfig,
		pullSecrets:  pullSecrets,
		installation: installation,
	}
}

type EksCloudwatchLogConfig struct {
	AwsId         []byte
	AwsKey        []byte
	AwsRegion     string
	GroupName     string
	StreamPrefix  string
	FetchInterval string
}

type fluentdComponent struct {
	lc           *operatorv1.LogCollector
	ls           *operatorv1.LogStorage
	esSecrets    []*corev1.Secret
	cluster      string
	s3Credential *S3Credential
	filters      *FluentdFilters
	eksConfig    *EksCloudwatchLogConfig
	pullSecrets  []*corev1.Secret
	installation *operatorv1.Installation
}

func (c *fluentdComponent) Objects() []runtime.Object {
	var objs []runtime.Object
	objs = append(objs,
		createNamespace(
			LogCollectorNamespace,
			c.installation.Spec.KubernetesProvider == operatorv1.ProviderOpenShift))
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, LogCollectorNamespace)...)
	if c.s3Credential != nil {
		objs = append(objs, c.s3CredentialSecret())
	}
	if c.filters != nil {
		objs = append(objs, c.filtersConfigMap())
	}
	if c.eksConfig != nil {
		objs = append(objs, c.eksLogForwarderServiceAccount(),
			c.eksLogForwarderSecret(),
			c.eksLogForwarderDeployment())
	}

	objs = append(objs, copySecrets(LogCollectorNamespace, c.esSecrets...)...)
	objs = append(objs, c.daemonset())

	return objs
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

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *fluentdComponent) daemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0
	maxUnavailable := intstr.FromInt(1)

	// Add Hashes of ConfigMap and Secrets as annotations so if either change
	// it will trigger a rolling update.
	annots := map[string]string{
		logStorageHashAnnotation:       c.ls.Status.ElasticsearchHash,
		elasticsearchSecretsAnnotation: secretsAnnotationHash(c.esSecrets...),
	}

	if c.s3Credential != nil {
		annots[s3CredentialHashAnnotation] = AnnotationHash(c.s3Credential)
	}
	if c.filters != nil {
		annots[filterHashAnnotation] = AnnotationHash(c.filters)
	}

	ds := appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fluentd-node",
			Namespace: LogCollectorNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "fluentd-node"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": "fluentd-node",
					},
					Annotations: annots,
				},
				Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
					NodeSelector:                  map[string]string{},
					Tolerations:                   c.tolerations(),
					ImagePullSecrets:              getImagePullSecretReferenceList(c.pullSecrets),
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					Containers:                    []corev1.Container{c.container()},
					Volumes:                       c.volumes(),
				}),
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}

	setCriticalPod(&(ds.Spec.Template))
	return &ds
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
		{MountPath: "/var/log/calico", Name: "var-log-calico"},
		{MountPath: "/etc/fluentd/elastic", Name: "elastic-ca-cert-volume"},
	}
	if c.filters != nil {
		if c.filters.Flow != "" {
			volumeMounts = append(volumeMounts,
				corev1.VolumeMount{
					Name:      "fluentd-filters",
					MountPath: "/etc/fluentd/flow-filters.conf",
					SubPath:   FluentdFilterFlowName,
				})
		}
		if c.filters.DNS != "" {
			volumeMounts = append(volumeMounts,
				corev1.VolumeMount{
					Name:      "fluentd-filters",
					MountPath: "/etc/fluentd/dns-filters.conf",
					SubPath:   FluentdFilterDNSName,
				})
		}
	}

	isPrivileged := true

	return ElasticsearchContainerDecorateENVVars(corev1.Container{
		Name:            "fluentd",
		Image:           constructImage(FluentdImageName, c.installation.Spec.Registry),
		Env:             envs,
		SecurityContext: &corev1.SecurityContext{Privileged: &isPrivileged},
		VolumeMounts:    volumeMounts,
		LivenessProbe:   c.liveness(),
		ReadinessProbe:  c.readiness(),
	}, c.cluster, ElasticsearchUserLogCollector)
}

func (c *fluentdComponent) envvars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "FLUENT_UID", Value: "0"},
		{Name: "ELASTIC_FLOWS_INDEX_SHARDS", Value: "5"},
		{Name: "ELASTIC_DNS_INDEX_SHARDS", Value: "5"},
		{Name: "FLOW_LOG_FILE", Value: "/var/log/calico/flowlogs/flows.log"},
		{Name: "DNS_LOG_FILE", Value: "/var/log/calico/dnslogs/dns.log"},
		{Name: "FLUENTD_ES_SECURE", Value: "true"},
	}

	if c.lc.Spec.AdditionalStores != nil {
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
		if syslog != nil {
			proto, host, port, _ := ParseEndpoint(syslog.Endpoint)
			envs = append(envs,
				corev1.EnvVar{Name: "SYSLOG_FLOW_LOG", Value: "true"},
				corev1.EnvVar{Name: "SYSLOG_AUDIT_LOG", Value: "true"},
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

	return envs
}

func (c *fluentdComponent) liveness() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: []string{"sh", "-c", "/bin/liveness.sh"},
			},
		},
	}
}

func (c *fluentdComponent) readiness() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: []string{"sh", "-c", "/bin/readiness.sh"},
			},
		},
	}
}

func (c *fluentdComponent) volumes() []corev1.Volume {
	dirOrCreate := corev1.HostPathDirectoryOrCreate

	volumes := []corev1.Volume{
		{
			Name: "var-log-calico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico",
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

	return volumes
}

func (c *fluentdComponent) eksLogForwarderServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: eksLogForwarderName, Namespace: LogCollectorNamespace},
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
		eksCloudwatchLogCredentialHashAnnotation: AnnotationHash(c.eksConfig),
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
		{Name: "EKS_CLOUDWATCH_LOG_FETCH_INTERVAL", Value: c.eksConfig.FetchInterval},
		{Name: "AWS_REGION", Value: c.eksConfig.AwsRegion},
		{Name: "AWS_ACCESS_KEY_ID", ValueFrom: envVarSourceFromSecret(EksLogForwarderSecret, EksLogForwarderAwsId, false)},
		{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: envVarSourceFromSecret(EksLogForwarderSecret, EksLogForwarderAwsKey, false)},
	}

	var eksLogForwarderReplicas int32 = 1

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      eksLogForwarderName,
			Namespace: LogCollectorNamespace,
			Labels: map[string]string{
				"k8s-app": eksLogForwarderName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &eksLogForwarderReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": eksLogForwarderName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      eksLogForwarderName,
					Namespace: LogCollectorNamespace,
					Labels: map[string]string{
						"k8s-app": eksLogForwarderName,
					},
					Annotations: annots,
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					ServiceAccountName: eksLogForwarderName,
					ImagePullSecrets:   getImagePullSecretReferenceList(c.pullSecrets),
					InitContainers: []corev1.Container{ElasticsearchContainerDecorateENVVars(corev1.Container{
						Name:         eksLogForwarderName + "-startup",
						Image:        constructImage(FluentdEksLogForwarderImageName, c.installation.Spec.Registry),
						Command:      []string{"/bin/eks-log-forwarder-startup"},
						Env:          envVars,
						VolumeMounts: c.eksLogForwarderVolumeMounts(),
					}, c.cluster, ElasticsearchUserEksLogForwarder)},
					Containers: []corev1.Container{ElasticsearchContainerDecorateENVVars(corev1.Container{
						Name:         eksLogForwarderName,
						Image:        constructImage(FluentdEksLogForwarderImageName, c.installation.Spec.Registry),
						Env:          envVars,
						VolumeMounts: c.eksLogForwarderVolumeMounts(),
					}, c.cluster, ElasticsearchUserEksLogForwarder)},
					Volumes: c.eksLogForwarderVolumes(),
				},
			},
		},
	}
}

func (c *fluentdComponent) eksLogForwarderVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		ElasticsearchDefaultVolumeMount(),
		{
			Name:      "plugin-statefile-dir",
			MountPath: "/fluentd/cloudwatch-logs/",
		},
		{
			Name:      "elastic-ca-cert-volume",
			MountPath: "/etc/fluentd/elastic/",
		},
	}
}

func (c *fluentdComponent) eksLogForwarderVolumes() []corev1.Volume {
	return []corev1.Volume{
		ElasticsearchDefaultVolume(),
		{
			Name: "plugin-statefile-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: nil,
			},
		},
	}
}
