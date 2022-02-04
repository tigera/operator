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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Elasticsearch metrics", func() {
	Context("Rendering resources", func() {
		var esConfig *relasticsearch.ClusterConfig
		var cfg *Config

		BeforeEach(func() {
			installation := &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}

			esConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)

			cfg = &Config{
				Installation: installation,
				PullSecrets:  []*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "pullsecret", Namespace: render.ElasticsearchNamespace}}},
				ESConfig:     esConfig,
				ESMetricsCredsSecret: &corev1.Secret{
					TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: common.OperatorNamespace()}},
				ESCertSecret: &corev1.Secret{
					TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: common.OperatorNamespace()}},
				ClusterDomain: "cluster.local",
				ServerTLS: &corev1.Secret{
					TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: ElasticsearchMetricsServerTLSSecret, Namespace: common.OperatorNamespace()}},
				TrustedBundle: &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: render.PrometheusCABundle, Namespace: render.ElasticsearchNamespace}},
			}
		})

		It("Successfully renders the Elasticsearch metrics resources", func() {

			component := ElasticsearchMetrics(cfg)
			Expect(component.ResolveImages(&operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{{
						Image:  "tigera/elasticsearch-metrics",
						Digest: "testdigest",
					}},
				},
			})).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, "", "v1", "Secret"},
				{ElasticsearchMetricsName, render.ElasticsearchNamespace, "", "v1", "Service"},
				{ElasticsearchMetricsName, render.ElasticsearchNamespace, "apps", "v1", "Deployment"},
				{render.PrometheusCABundle, render.ElasticsearchNamespace, "", "v1", "ConfigMap"},
				{ElasticsearchMetricsName, render.ElasticsearchNamespace, "", "v1", "ServiceAccount"},
				{ElasticsearchMetricsServerTLSSecret, render.ElasticsearchNamespace, "", "v1", "Secret"},
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))
			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			deploy := rtest.GetResource(resources, ElasticsearchMetricsName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			service := rtest.GetResource(resources, ElasticsearchMetricsName, render.ElasticsearchNamespace, "", "v1", "Service").(*corev1.Service)
			configMap := rtest.GetResource(resources, render.PrometheusCABundle, render.ElasticsearchNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
			secret := rtest.GetResource(resources, ElasticsearchMetricsServerTLSSecret, render.ElasticsearchNamespace, "", "v1", "Secret").(*corev1.Secret)

			expectedService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ElasticsearchMetricsName,
					Namespace: render.ElasticsearchNamespace,
					Labels:    map[string]string{"k8s-app": ElasticsearchMetricsName},
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{"k8s-app": ElasticsearchMetricsName},
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
			expectedDeploy := &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      ElasticsearchMetricsName,
					Namespace: render.ElasticsearchNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.Int32ToPtr(1),
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"k8s-app": ElasticsearchMetricsName},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{"k8s-app": ElasticsearchMetricsName},
							Annotations: map[string]string{
								"hash.operator.tigera.io/elasticsearch-configmap": "ae0242f242af19c4916434cb08e8f68f8c15f61d",
								"hash.operator.tigera.io/elasticsearch-secrets":   "9718549725e37ca6a5f12ba2405392a04d7b5521",
							},
						},
						Spec: corev1.PodSpec{
							ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pullsecret"}},
							Containers: []corev1.Container{{
								Name:    ElasticsearchMetricsName,
								Image:   "testregistry.com/tigera/elasticsearch-metrics@testdigest",
								Command: []string{"/bin/elasticsearch_exporter"},
								Args: []string{"--es.uri=https://$(ELASTIC_USERNAME):$(ELASTIC_PASSWORD)@$(ELASTIC_HOST):$(ELASTIC_PORT)",
									"--es.all", "--es.indices", "--es.indices_settings", "--es.shards", "--es.cluster_settings",
									"--es.timeout=30s", "--es.ca=$(ELASTIC_CA)", "--web.listen-address=:9081",
									"--web.telemetry-path=/metrics", "--tls.key=/tls/tls.key", "--tls.crt=/tls/tls.crt", "--ca.crt=/ca/tls.crt"},
								Env: []corev1.EnvVar{
									{Name: "ELASTIC_INDEX_SUFFIX", Value: "cluster"},
									{Name: "ELASTIC_SCHEME", Value: "https"},
									{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
									{Name: "ELASTIC_PORT", Value: "9200"},
									{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
									{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
									{
										Name: "ELASTIC_USER",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "tigera-ee-elasticsearch-metrics-elasticsearch-access",
												},
												Key: "username",
											},
										},
									},
									{
										Name: "ELASTIC_USERNAME",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "tigera-ee-elasticsearch-metrics-elasticsearch-access",
												},
												Key: "username",
											},
										},
									},
									{
										Name: "ELASTIC_PASSWORD",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "tigera-ee-elasticsearch-metrics-elasticsearch-access",
												},
												Key: "password",
											},
										},
									},
									{Name: "ELASTIC_CA", Value: "/etc/ssl/elastic/ca.pem"},
									{Name: "ES_CA_CERT", Value: "/etc/ssl/elastic/ca.pem"},
									{Name: "ES_CURATOR_BACKEND_CERT", Value: "/etc/ssl/elastic/ca.pem"},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      ElasticsearchMetricsServerTLSSecret,
										MountPath: "/tls",
										ReadOnly:  true,
									},
									{
										Name:      render.PrometheusCABundle,
										MountPath: "/ca",
										ReadOnly:  true,
									},
									{Name: "elastic-ca-cert-volume", MountPath: "/etc/ssl/elastic/"},
								},
							}},
							ServiceAccountName: ElasticsearchMetricsName,
							Volumes: []corev1.Volume{
								{
									Name: ElasticsearchMetricsServerTLSSecret,
									VolumeSource: corev1.VolumeSource{
										Secret: &corev1.SecretVolumeSource{SecretName: ElasticsearchMetricsServerTLSSecret, DefaultMode: ptr.Int32ToPtr(420)}},
								},
								{
									Name: render.PrometheusCABundle,
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: render.PrometheusCABundle},
										},
									},
								},
								{
									Name: "elastic-ca-cert-volume",
									VolumeSource: corev1.VolumeSource{
										Secret: &corev1.SecretVolumeSource{
											SecretName: "tigera-secure-es-gateway-http-certs-public",
											Items:      []corev1.KeyToPath{{Key: "tls.crt", Path: "ca.pem"}},
										},
									},
								},
							},
						},
					},
				},
			}
			expectedConfigMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: render.PrometheusCABundle, Namespace: render.ElasticsearchNamespace}}
			expectedSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ElasticsearchMetricsServerTLSSecret, Namespace: render.ElasticsearchNamespace}}

			Expect(service.Spec).To(Equal(expectedService.Spec))
			Expect(configMap.Data).To(Equal(expectedConfigMap.Data))
			Expect(secret.Data).To(Equal(expectedSecret.Data))
			Expect(deploy.Annotations).To(Equal(expectedDeploy.Annotations))
			Expect(deploy.Spec.Template.Spec.Volumes).To(Equal(expectedDeploy.Spec.Template.Spec.Volumes))
			Expect(deploy.Spec.Template.Spec.Containers[0].VolumeMounts).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].VolumeMounts))
			Expect(deploy.Spec.Template.Spec.Containers[0].Args).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].Args))
			Expect(deploy.Spec.Template.Spec.Containers[0].Env).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].Env))
			Expect(deploy.Spec.Template.Spec.Containers[0].Command).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].Command))
		})

		It("should apply controlPlaneNodeSelector correctly", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"foo": "bar"}

			component := ElasticsearchMetrics(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, ElasticsearchMetricsName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should apply controlPlaneTolerations correctly", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{t}
			component := ElasticsearchMetrics(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, ElasticsearchMetricsName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		})
	})
})
