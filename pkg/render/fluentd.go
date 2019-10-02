package render

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	LogCollectorNamespace = "tigera-fluentd"
)

func Fluentd(
	lc *operatorv1.LogCollector,
	monitoring *operatorv1.MonitoringConfiguration,
	pullSecrets []*corev1.Secret,
	provider operatorv1.Provider,
	registry string,
) Component {
	return &fluentdComponent{
		lc:          lc,
		monitoring:  monitoring,
		pullSecrets: pullSecrets,
		provider:    provider,
		registry:    registry,
	}
}

type fluentdComponent struct {
	lc          *operatorv1.LogCollector
	monitoring  *operatorv1.MonitoringConfiguration
	pullSecrets []*corev1.Secret
	provider    operatorv1.Provider
	registry    string
}

func (c *fluentdComponent) Objects() []runtime.Object {
	var objs []runtime.Object
	objs = append(objs, createNamespace(LogCollectorNamespace, c.provider == operatorv1.ProviderOpenShift))
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, LogCollectorNamespace)...)
	objs = append(objs, c.daemonset())

	return objs
}

func (c *fluentdComponent) Ready() bool {
	return true
}

// consoleManagerDeployment creates a deployment for the Tigera Secure console manager component.
func (c *fluentdComponent) daemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0
	maxUnavailable := intstr.FromInt(1)

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
				},
				Spec: corev1.PodSpec{
					NodeSelector:                  map[string]string{},
					Tolerations:                   c.tolerations(),
					ImagePullSecrets:              getImagePullSecretReferenceList(c.pullSecrets),
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					Containers:                    []corev1.Container{c.container()},
					Volumes:                       c.volumes(),
				},
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
		//{MountPath: "/etc/fluend/elastic", Name: "elastic-ca-cert-volume"},
	}

	return corev1.Container{
		Name:           "fluentd",
		Image:          constructImage(FluentdImageName, c.registry),
		Env:            envs,
		VolumeMounts:   volumeMounts,
		LivenessProbe:  c.liveness(),
		ReadinessProbe: c.readiness(),
	}
}

func (c *fluentdComponent) envvars() []corev1.EnvVar {
	esScheme, esHost, esPort, _ := ParseEndpoint(c.monitoring.Spec.Elasticsearch.Endpoint)
	envs := []corev1.EnvVar{
		{Name: "FLUENT_UID", Value: "0"},
		{Name: "ELASTIC_FLOWS_INDEX_SHARDS", Value: "5"},
		{Name: "ELASTIC_DNS_INDEX_SHARDS", Value: "5"},
		{Name: "ELASTIC_INDEX_SUFFIX", Value: c.monitoring.Spec.ClusterName},
		{Name: "FLOW_LOG_FILE", Value: "/var/log/calico/flowlogs/flows.log"},
		{Name: "DNS_LOG_FILE", Value: "/var/log/calico/dnslogs/dns.log"},
		{Name: "ELASTIC_SCHEME", Value: esScheme},
		{Name: "ELASTIC_HOST", Value: esHost},
		{Name: "ELASTIC_PORT", Value: esPort},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{Name: "FLUENTD_ES_SECURE", Value: "false"},
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

	return volumes
}
