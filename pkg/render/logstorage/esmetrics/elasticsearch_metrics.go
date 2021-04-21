// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package esmetrics

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	ElasticsearchMetricsSecret = "tigera-ee-elasticsearch-metrics-elasticsearch-access"
)

func ElasticsearchMetrics(
	installation *operatorv1.InstallationSpec,
	pullSecrets []*corev1.Secret,
	esConfig *relasticsearch.ClusterConfig,
	esMetricsCredsSecret *corev1.Secret,
	esCertSecret *corev1.Secret,
	clusterDomain string,
) render.Component {
	return &elasticsearchMetrics{
		installation:         installation,
		pullSecrets:          pullSecrets,
		esConfig:             esConfig,
		esMetricsCredsSecret: esMetricsCredsSecret,
		esCertSecret:         esCertSecret,
		clusterDomain:        clusterDomain,
	}
}

type elasticsearchMetrics struct {
	installation         *operatorv1.InstallationSpec
	pullSecrets          []*corev1.Secret
	esMetricsImage       string
	esMetricsCredsSecret *corev1.Secret
	esCertSecret         *corev1.Secret
	esConfig             *relasticsearch.ClusterConfig
	clusterDomain        string
}

func (e *elasticsearchMetrics) ResolveImages(is *operatorv1.ImageSet) error {
	var err error

	reg := e.installation.Registry
	path := e.installation.ImagePath

	e.esMetricsImage, err = components.GetReference(components.ComponentElasticsearchMetrics, reg, path, is)

	return err
}

func (e *elasticsearchMetrics) Objects() (objsToCreate, objsToDelete []client.Object) {
	toCreate := secret.ToRuntimeObjects(
		secret.CopyToNamespace(render.ElasticsearchNamespace, e.esMetricsCredsSecret)...,
	)
	toCreate = append(toCreate, e.metricsService(), e.metricsDeployment())

	return toCreate, nil
}

func (e *elasticsearchMetrics) Ready() bool {
	return true
}

func (e *elasticsearchMetrics) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e *elasticsearchMetrics) metricsService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-elasticsearch-metrics",
			Namespace: render.ElasticsearchNamespace,
			Labels: map[string]string{
				"k8s-app": "tigera-elasticsearch-metrics",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": "tigera-elasticsearch-metrics",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics-port",
					Port:       9081,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(9081),
				},
			},
		},
	}
}

func (e elasticsearchMetrics) metricsDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-elasticsearch-metrics",
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "tigera-elasticsearch-metrics",
				},
			},
			Template: *relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": "tigera-elasticsearch-metrics",
					},
				},
				Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
					ImagePullSecrets: secret.GetReferenceList(e.pullSecrets),
					Containers: []corev1.Container{
						relasticsearch.ContainerDecorate(
							corev1.Container{
								Name:    "tigera-elasticsearch-metrics",
								Image:   e.esMetricsImage,
								Command: []string{"/bin/elasticsearch_exporter"},
								Args: []string{"--es.uri=https://$(ELASTIC_USERNAME):$(ELASTIC_PASSWORD)@$(ELASTIC_HOST):$(ELASTIC_PORT)",
									"--es.all", "--es.indices", "--es.indices_settings", "--es.shards", "--es.cluster_settings",
									"--es.timeout=30s", "--es.ca=$(ELASTIC_CA)", "--web.listen-address=:9081",
									"--web.telemetry-path=/metrics"},
							}, render.DefaultElasticsearchClusterName, ElasticsearchMetricsSecret,
							e.clusterDomain, e.SupportedOSType(),
						),
					},
				}),
			}, e.esConfig, []*corev1.Secret{e.esMetricsCredsSecret, e.esCertSecret}).(*corev1.PodTemplateSpec),
		},
	}
}
