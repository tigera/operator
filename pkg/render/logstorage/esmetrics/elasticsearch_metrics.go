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
	"fmt"
	"github.com/tigera/operator/pkg/dns"
	"strings"

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
	ElasticsearchMetricsSecret          = "tigera-ee-elasticsearch-metrics-elasticsearch-access"
	ElasticsearchMetricsServerTLSSecret = "tigera-ee-elasticsearch-metrics-tls"
	ElasticsearchMetricsName            = "tigera-elasticsearch-metrics"
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
	ServerTLS            *corev1.Secret
	TrustedBundle        *corev1.ConfigMap
}

type elasticsearchMetrics struct {
	cfg            *Config
	esMetricsImage string
	csrImage       string
}

func (e *elasticsearchMetrics) ResolveImages(is *operatorv1.ImageSet) error {
	var err error

	reg := e.cfg.Installation.Registry
	path := e.cfg.Installation.ImagePath
	prefix := e.cfg.Installation.ImagePrefix

	var errMsgs []string

	e.esMetricsImage, err = components.GetReference(components.ComponentElasticsearchMetrics, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if e.cfg.Installation.CertificateManagement != nil {
		e.csrImage, err = render.ResolveCSRInitImage(e.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}

	return err
}

func (e *elasticsearchMetrics) Objects() (objsToCreate, objsToDelete []client.Object) {
	toCreate := secret.ToRuntimeObjects(
		secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.ESMetricsCredsSecret)...,
	)
	toCreate = append(toCreate, e.metricsService(), e.metricsDeployment(), e.cfg.TrustedBundle, e.serviceAccount())

	if e.cfg.Installation.CertificateManagement == nil {
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.ServerTLS)...)...)
		objsToDelete = append(objsToDelete, render.CSRClusterRoleBinding(ElasticsearchMetricsName, render.ElasticsearchNamespace))
	} else {
		objsToDelete = append(objsToDelete, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ElasticsearchMetricsServerTLSSecret, Namespace: render.ElasticsearchNamespace}})
		toCreate = append(toCreate, render.CSRClusterRoleBinding(ElasticsearchMetricsName, render.ElasticsearchNamespace))
	}

	return toCreate, objsToDelete
}

func (e elasticsearchMetrics) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsName,
			Namespace: render.ElasticsearchNamespace,
		},
	}
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
			Name:      ElasticsearchMetricsName,
			Namespace: render.ElasticsearchNamespace,
			Labels: map[string]string{
				"k8s-app": ElasticsearchMetricsName,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": ElasticsearchMetricsName,
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
	var initContainers []corev1.Container

	annotations := map[string]string{
		"k8s-app":                           ElasticsearchMetricsName,
		render.PrometheusCABundleAnnotation: rmeta.AnnotationHash(e.cfg.TrustedBundle.Data),
	}
	if e.cfg.Installation.CertificateManagement != nil {
		initContainers = append(initContainers,
			render.CreateCSRInitContainer(
				e.cfg.Installation.CertificateManagement,
				e.csrImage,
				ElasticsearchMetricsServerTLSSecret,
				ElasticsearchMetricsServerTLSSecret,
				corev1.TLSPrivateKeyKey,
				corev1.TLSCertKey,
				dns.GetServiceDNSNames(ElasticsearchMetricsName, render.ElasticsearchNamespace, e.cfg.ClusterDomain),
				render.ElasticsearchNamespace),
		)
	}

	if e.cfg.ServerTLS != nil {
		annotations[fmt.Sprintf("hash.operator.tigera.io/%s", e.cfg.ServerTLS.Name)] = rmeta.AnnotationHash(e.cfg.ServerTLS.Data)
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": ElasticsearchMetricsName,
				},
			},
			Template: *relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: annotations,
				},
				Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
					Tolerations:        e.cfg.Installation.ControlPlaneTolerations,
					NodeSelector:       e.cfg.Installation.ControlPlaneNodeSelector,
					ImagePullSecrets:   secret.GetReferenceList(e.cfg.PullSecrets),
					ServiceAccountName: ElasticsearchMetricsName,
					InitContainers:     initContainers,
					Containers: []corev1.Container{
						relasticsearch.ContainerDecorate(
							corev1.Container{
								Name:    ElasticsearchMetricsName,
								Image:   e.esMetricsImage,
								Command: []string{"/bin/elasticsearch_exporter"},
								Args: []string{"--es.uri=https://$(ELASTIC_USERNAME):$(ELASTIC_PASSWORD)@$(ELASTIC_HOST):$(ELASTIC_PORT)",
									"--es.all", "--es.indices", "--es.indices_settings", "--es.shards", "--es.cluster_settings",
									"--es.timeout=30s", "--es.ca=$(ELASTIC_CA)", "--web.listen-address=:9081",
									"--web.telemetry-path=/metrics", "--tls.key=/tls/tls.key", "--tls.crt=/tls/tls.crt", "--ca.crt=/ca/tls.crt"},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      ElasticsearchMetricsServerTLSSecret,
										MountPath: "/tls",
										ReadOnly:  true,
									},
									{
										Name:      e.cfg.TrustedBundle.Name,
										MountPath: "/ca",
										ReadOnly:  true,
									},
								},
							}, render.DefaultElasticsearchClusterName, ElasticsearchMetricsSecret,
							e.cfg.ClusterDomain, e.SupportedOSType(),
						),
					},
					Volumes: []corev1.Volume{
						{
							Name:         ElasticsearchMetricsServerTLSSecret,
							VolumeSource: render.CertificateVolumeSource(e.cfg.Installation.CertificateManagement, ElasticsearchMetricsServerTLSSecret),
						},
						{
							Name: e.cfg.TrustedBundle.Name,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: e.cfg.TrustedBundle.Name},
								},
							},
						},
					},
				}),
			}, e.cfg.ESConfig, []*corev1.Secret{e.cfg.ESMetricsCredsSecret, e.cfg.ESCertSecret}).(*corev1.PodTemplateSpec),
		},
	}
}
