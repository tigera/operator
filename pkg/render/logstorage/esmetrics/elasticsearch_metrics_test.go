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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
)

var _ = Describe("Elasticsearch metrics", func() {
	Context("Rendering resources", func() {
		var installation *operatorv1.InstallationSpec
		var esConfig *relasticsearch.ClusterConfig

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}

			esConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
		})

		It("Successfully renders the Elasticsearch metrics resources", func() {
			expectedResources := []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.TigeraElasticsearchCertSecret,
						Namespace: render.ElasticsearchNamespace,
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-elasticsearch-metrics",
						Namespace: render.ElasticsearchNamespace,
						Labels:    map[string]string{"k8s-app": "tigera-elasticsearch-metrics"},
					},
					Spec: corev1.ServiceSpec{
						Selector: map[string]string{"k8s-app": "tigera-elasticsearch-metrics"},
						Ports: []corev1.ServicePort{
							{
								Name:       "metrics-port",
								Port:       9081,
								Protocol:   corev1.ProtocolTCP,
								TargetPort: intstr.FromInt(9081),
							},
						},
					},
				},
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-elasticsearch-metrics",
						Namespace: render.ElasticsearchNamespace,
					},
					Spec: appsv1.DeploymentSpec{
						Replicas: ptr.Int32ToPtr(1),
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"k8s-app": "tigera-elasticsearch-metrics"},
						},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: map[string]string{"k8s-app": "tigera-elasticsearch-metrics"},
								Annotations: map[string]string{
									"hash.operator.tigera.io/elasticsearch-configmap": "ae0242f242af19c4916434cb08e8f68f8c15f61d",
									"hash.operator.tigera.io/elasticsearch-secrets":   "9718549725e37ca6a5f12ba2405392a04d7b5521",
								},
							},
							Spec: corev1.PodSpec{
								ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pullsecret"}},
								Containers: []corev1.Container{{
									Name:    "tigera-elasticsearch-metrics",
									Image:   "testregistry.com/tigera/elasticsearch-metrics@testdigest",
									Command: []string{"/bin/elasticsearch_exporter"},
									Args: []string{"--es.uri=https://$(ELASTIC_USERNAME):$(ELASTIC_PASSWORD)@$(ELASTIC_HOST):$(ELASTIC_PORT)",
										"--es.all", "--es.indices", "--es.indices_settings", "--es.shards", "--es.cluster_settings",
										"--es.timeout=30s", "--es.ca=$(ELASTIC_CA)", "--web.listen-address=:9081",
										"--web.telemetry-path=/metrics"},
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
										{Name: "elastic-ca-cert-volume", MountPath: "/etc/ssl/elastic/"},
									},
								}},

								Volumes: []corev1.Volume{{
									Name: "elastic-ca-cert-volume",
									VolumeSource: corev1.VolumeSource{
										Secret: &corev1.SecretVolumeSource{
											SecretName: "tigera-secure-es-gateway-http-certs-public",
											Items:      []corev1.KeyToPath{{Key: "tls.crt", Path: "ca.pem"}},
										},
									},
								}},
							},
						},
					},
				},
			}

			component := ElasticsearchMetrics(installation,
				[]*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "pullsecret", Namespace: render.ElasticsearchNamespace}}},
				esConfig,
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: common.OperatorNamespace()}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: common.OperatorNamespace()}},
				"cluster.local")

			Expect(component.ResolveImages(&operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{{
						Image:  "tigera/elasticsearch-metrics",
						Digest: "testdigest",
					}},
				},
			})).ShouldNot(HaveOccurred())

			createdResources, _ := component.Objects()
			Expect(createdResources).Should(Equal(expectedResources))
		})
	})
})
