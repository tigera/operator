package component

import (
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/render/common/secret"

	"github.com/tigera/operator/pkg/ptr"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/apimachinery/pkg/util/intstr"
)

func ElasticsearchMetrics(
	installation *operatorv1.InstallationSpec,
	clusterConfig *relasticsearch.ClusterConfig,
	esMetricsCredsSecret *corev1.Secret,
	esCertSecret *corev1.Secret,
	clusterDomain string,
) render.Component {
	return &elasticsearchMetrics{
		installation:         installation,
		clusterConfig:        clusterConfig,
		esMetricsCredsSecret: esMetricsCredsSecret,
		esCertSecret:         esCertSecret,
		clusterDomain:        clusterDomain,
	}
}

type elasticsearchMetrics struct {
	installation         *operatorv1.InstallationSpec
	esMetricsImage       string
	esMetricsCredsSecret *corev1.Secret
	esCertSecret         *corev1.Secret
	clusterConfig        *relasticsearch.ClusterConfig
	clusterDomain        string
}

func (e *elasticsearchMetrics) ResolveImages(is *operatorv1.ImageSet) error {
	var err error
	var errMsgs []string

	reg := e.installation.Registry
	path := e.installation.ImagePath

	e.esMetricsImage, err = components.GetReference(components.ComponentElasticsearchMetrics, reg, path, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (e *elasticsearchMetrics) Objects() (objsToCreate, objsToDelete []client.Object) {
	var toCreate []client.Object
	toCreate = append(toCreate, secret.ToRuntimeObjects(
		secret.CopyToNamespace(render.ElasticsearchNamespace, e.esMetricsCredsSecret)...,
	)...)

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
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
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
					Containers: []corev1.Container{
						relasticsearch.ContainerDecorate(
							corev1.Container{
								Name:            "tigera-elasticsearch-metrics",
								Image:           e.esMetricsImage,
								ImagePullPolicy: "Always",
								Command:         []string{"/bin/elasticsearch_exporter"},
								Args: []string{"--es.uri=https://$(ELASTIC_USERNAME):$(ELASTIC_PASSWORD)@$(ELASTIC_HOST):$(ELASTIC_PORT)",
									"--es.all", "--es.indices", "--es.indices_settings", "--es.shards", "--es.cluster_settings",
									"--es.timeout=30s", "--es.ca=$(ELASTIC_CA)", "--web.listen-address=:9081",
									"--web.telemetry-path=/metrics"},
							}, render.DefaultElasticsearchClusterName, render.ElasticsearchMetricsSecret,
							e.clusterDomain, e.SupportedOSType(),
						),
					},
				}),
			}, e.clusterConfig, []*corev1.Secret{e.esMetricsCredsSecret, e.esCertSecret}).(*corev1.PodTemplateSpec),
		},
	}
}
