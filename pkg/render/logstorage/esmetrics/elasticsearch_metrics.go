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

func ElasticsearchMetrics(cfg *Config) render.Component {
	return &elasticsearchMetrics{
		cfg: cfg,
	}
}

type Config struct {
	Installation         *operatorv1.InstallationSpec
	PullSecrets          []*corev1.Secret
	ESConfig             *relasticsearch.ClusterConfig
	ESMetricsCredsSecret *corev1.Secret
	ESCertSecret         *corev1.Secret
	ClusterDomain        string
}

type elasticsearchMetrics struct {
	cfg            *Config
	esMetricsImage string
}

func (e *elasticsearchMetrics) ResolveImages(is *operatorv1.ImageSet) error {
	var err error

	reg := e.cfg.Installation.Registry
	path := e.cfg.Installation.ImagePath
	prefix := e.cfg.Installation.ImagePrefix

	e.esMetricsImage, err = components.GetReference(components.ComponentElasticsearchMetrics, reg, path, prefix, is)

	return err
}

func (e *elasticsearchMetrics) Objects() (objsToCreate, objsToDelete []client.Object) {
	toCreate := secret.ToRuntimeObjects(
		secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.ESMetricsCredsSecret)...,
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
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-elasticsearch-metrics",
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Template: *relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
				Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
					Tolerations:      e.cfg.Installation.ControlPlaneTolerations,
					NodeSelector:     e.cfg.Installation.ControlPlaneNodeSelector,
					ImagePullSecrets: secret.GetReferenceList(e.cfg.PullSecrets),
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
							e.cfg.ClusterDomain, e.SupportedOSType(),
						),
					},
				}),
			}, e.cfg.ESConfig, []*corev1.Secret{e.cfg.ESMetricsCredsSecret, e.cfg.ESCertSecret}).(*corev1.PodTemplateSpec),
		},
	}
}
