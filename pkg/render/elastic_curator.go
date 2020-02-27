// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

// These constants should be moved to `logstorage_types` in 2.6.1
const (
	// As soon as the total disk utilization exceeds the max-total-storage-percent,
	// indices will be removed starting with the oldest. Picking a low value leads
	// to low disk utilization, while a high value might result in unexpected
	// behaviour.
	// Default: 80
	// +optional
	maxTotalStoragePercent int32 = 80

	// TSEE will remove dns and flow log indices once the combined data exceeds this
	// threshold. The default value (70% of the cluster size) is used because flow
	// logs and dns logs often use the most disk space; this allows compliance and
	// security indices to be retained longer. The oldest indices are removed first.
	// Set this value to be lower than or equal to, the value for
	// max-total-storage-pct.
	// Default: 70
	// +optional
	maxLogsStoragePercent int32 = 70
)

func ElasticCurator(logStorage operatorv1.LogStorage, esSecrets, pullSecrets []*corev1.Secret, installcr *operatorv1.Installation, clusterName string) Component {
	return &elasticCuratorComponent{
		logStorage:  logStorage,
		pullSecrets: pullSecrets,
		esSecrets:   esSecrets,
		installcr:   installcr,
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
	installcr   *operatorv1.Installation
	clusterName string
}

func (ec *elasticCuratorComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		ec.cronJob(),
	}
	objs = append(objs, copyImagePullSecrets(ec.pullSecrets, ElasticsearchNamespace)...)
	return append(objs, secretsToRuntimeObjects(copySecrets(ElasticsearchNamespace, ec.esSecrets...)...)...)
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
	}

	const schedule = "@hourly"

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
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
							Containers: []corev1.Container{
								ElasticsearchContainerDecorate(corev1.Container{
									Name:          EsCuratorName,
									Image:         constructImage(EsCuratorImageName, ec.installcr.Spec.Registry, ec.installcr.Spec.ImagePath),
									Env:           ec.envVars(),
									LivenessProbe: elasticCuratorLivenessProbe,
									SecurityContext: &v1.SecurityContext{
										RunAsNonRoot:             &f,
										AllowPrivilegeEscalation: &f,
									},
								}, ec.clusterName, ElasticsearchCuratorUserSecret),
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
		{Name: "EE_FLOWS_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*ec.logStorage.Spec.Retention.Flows)},
		{Name: "EE_AUDIT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*ec.logStorage.Spec.Retention.AuditReports)},
		{Name: "EE_SNAPSHOT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*ec.logStorage.Spec.Retention.Snapshots)},
		{Name: "EE_COMPLIANCE_REPORT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*ec.logStorage.Spec.Retention.ComplianceReports)},
		{Name: "EE_MAX_TOTAL_STORAGE_PCT", Value: fmt.Sprint(maxTotalStoragePercent)},
		{Name: "EE_MAX_LOGS_STORAGE_PCT", Value: fmt.Sprint(maxLogsStoragePercent)},
	}
}
