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
	LogCollectorNamespace         = "tigera-fluentd"
	FluentdFilterConfigMapName    = "fluentd-filters"
	FluentdFilterFlowName         = "flow"
	FluentdFilterDNSName          = "dns"
	S3FluentdSecretName           = "log-collector-s3-credentials"
	S3KeyIdName                   = "key-id"
	S3KeySecretName               = "key-secret"
	filterHashAnnotation          = "hash.operator.tigera.io/fluentd-filters"
	s3CredentialHashAnnotation    = "hash.operator.tigera.io/s3-credentials"
	fluentdDefaultFlush           = "5s"
	ElasticsearchUserLogCollector = "tigera-fluentd"
	ElasticsearchHTTPEndpoint     = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
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
	esSecrets []*corev1.Secret,
	cluster string,
	s3C *S3Credential,
	f *FluentdFilters,

	pullSecrets []*corev1.Secret,
	installation *operatorv1.Installation,
) Component {
	return &fluentdComponent{
		lc:           lc,
		esSecrets:    esSecrets,
		cluster:      cluster,
		s3Credential: s3C,
		filters:      f,
		pullSecrets:  pullSecrets,
		installation: installation,
	}
}

type fluentdComponent struct {
	lc           *operatorv1.LogCollector
	esSecrets    []*corev1.Secret
	cluster      string
	s3Credential *S3Credential
	filters      *FluentdFilters
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
	annots := make(map[string]string)
	if c.s3Credential != nil {
		annots[s3CredentialHashAnnotation] = annotationHash(c.s3Credential)
	}
	if c.filters != nil {
		annots[filterHashAnnotation] = annotationHash(c.filters)
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

	if c.lc.Spec.S3 != nil {
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
			corev1.EnvVar{Name: "S3_BUCKET_NAME", Value: c.lc.Spec.S3.BucketName},
			corev1.EnvVar{Name: "AWS_REGION", Value: c.lc.Spec.S3.Region},
			corev1.EnvVar{Name: "S3_BUCKET_PATH", Value: c.lc.Spec.S3.BucketPath},
			corev1.EnvVar{Name: "S3_FLUSH_INTERVAL", Value: fluentdDefaultFlush},
		)
	}
	if c.lc.Spec.Syslog != nil {
		proto, host, port, _ := ParseEndpoint(c.lc.Spec.Syslog.Endpoint)
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
		if c.lc.Spec.Syslog.PacketSize != nil {
			envs = append(envs,
				corev1.EnvVar{
					Name:  "SYSLOG_PACKET_SIZE",
					Value: fmt.Sprintf("%d", *c.lc.Spec.Syslog.PacketSize),
				},
			)
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
