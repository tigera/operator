package render

import (
	"strconv"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	batchv1 "k8s.io/api/batch/v1"
	batch "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	EsCuratorName = "elastic-curator"
)

func ElasticCurator(logStorage operatorv1.LogStorage, esSecrets, pullSecrets []*corev1.Secret, registry, clusterName string) Component {
	return &elasticCuratorComponent{
		logStorage:  logStorage,
		pullSecrets: pullSecrets,
		esSecrets:   esSecrets,
		registry:    registry,
		clusterName: clusterName,
	}
}

func (es *elasticCuratorComponent) Ready() bool {
	return true
}

type elasticCuratorComponent struct {
	logStorage  operatorv1.LogStorage
	esSecrets   []*corev1.Secret
	pullSecrets []*corev1.Secret
	registry    string
	clusterName string
}

func (ec *elasticCuratorComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		ec.cronJob(),
	}
	objs = append(objs, copyImagePullSecrets(ec.pullSecrets, ElasticsearchNamespace)...)
	return append(objs, copySecrets(ElasticsearchNamespace, ec.esSecrets...)...)

}

func (ec elasticCuratorComponent) cronJob() *batch.CronJob {
	var f = false
	var elasticCuratorLivenessProbe = &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: []string{
					"/usr/bin/curator",
					"--config",
					"/curator/curator_config.yaml",
					"--dry-run",
					"/curator/curator_action.yaml",
				},
			},
		},
		// TODO: confirm / deny hunch that these numbers are just high because there previously
		// wasn't a way to wait until elasticsearch was ready
		InitialDelaySeconds: 60,
		PeriodSeconds:       60,
	}

	const schedule = "@daily"

	return &batch.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsCuratorName,
			Namespace: ElasticsearchNamespace,
		},
		Spec: batch.CronJobSpec{
			Schedule: schedule,
			JobTemplate: batch.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: EsCuratorName,
				},
				// Template: batch.JobTemplateSpec{},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
							Containers: []corev1.Container{
								ElasticsearchContainerDecorate(corev1.Container{
									Name:  EsCuratorName,
									Image: constructImage(EsCuratorImageName, ec.registry),
									// TODO: add es connection settings
									Env:           ec.envVars(),
									LivenessProbe: elasticCuratorLivenessProbe,
									SecurityContext: &v1.SecurityContext{
										RunAsNonRoot:             &f,
										AllowPrivilegeEscalation: &f,
									},
								}, ec.clusterName, ElasticsearchUserCurator),
							},
							ImagePullSecrets: getImagePullSecretReferenceList(ec.pullSecrets),
							RestartPolicy:    v1.RestartPolicyOnFailure,
						}),
					},
				},
			},
		},
	}
}

func (ec elasticCuratorComponent) envVars() []corev1.EnvVar {
	return []corev1.EnvVar{
		// TODO: handle nil
		{Name: "EE_FLOWS_INDEX_RETENTION_PERIOD", Value: strconv.Itoa(ec.logStorage.Spec.Retention.FlowRetention)},
		{Name: "EE_AUDIT_INDEX_RETENTION_PERIOD", Value: strconv.Itoa(ec.logStorage.Spec.Retention.AuditRetention)},
		{Name: "EE_SNAPSHOT_INDEX_RETENTION_PERIOD", Value: strconv.Itoa(ec.logStorage.Spec.Retention.SnapshotRetention)},
		{Name: "EE_COMPLIANCE_REPORT_INDEX_RETENTION_PERIOD", Value: strconv.Itoa(ec.logStorage.Spec.Retention.ComplianceReportRetention)},
	}
}
