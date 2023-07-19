// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Elasticsearch metrics", func() {
	Context("Rendering resources", func() {
		var esConfig *relasticsearch.ClusterConfig
		var cfg *Config
		expectedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/es-metrics.json")
		expectedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/es-metrics_ocp.json")

		BeforeEach(func() {
			installation := &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}

			esConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			cli := fake.NewClientBuilder().WithScheme(scheme).Build()
			certificateManager, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			bundle := certificateManager.CreateTrustedBundle()
			secret, err := certificateManager.GetOrCreateKeyPair(cli, ElasticsearchMetricsServerTLSSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())

			cfg = &Config{
				Installation: installation,
				PullSecrets:  []*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "pullsecret", Namespace: render.ElasticsearchNamespace}}},
				ESConfig:     esConfig,
				ESMetricsCredsSecret: &corev1.Secret{
					TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchGatewaySecret, Namespace: common.OperatorNamespace()}},
				ClusterDomain: "cluster.local",
				ServerTLS:     secret,
				TrustedBundle: bundle,
				UsePSP:        true,
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
				{ElasticsearchMetricsPolicyName, render.ElasticsearchNamespace, "projectcalico.org", "v3", "NetworkPolicy"},
				{render.TigeraElasticsearchGatewaySecret, render.ElasticsearchNamespace, "", "v1", "Secret"},
				{ElasticsearchMetricsName, render.ElasticsearchNamespace, "", "v1", "Service"},
				{ElasticsearchMetricsName, render.ElasticsearchNamespace, "apps", "v1", "Deployment"},
				{ElasticsearchMetricsName, render.ElasticsearchNamespace, "", "v1", "ServiceAccount"},
				{"tigera-elasticsearch-metrics", "tigera-elasticsearch", "rbac.authorization.k8s.io", "v1", "Role"},
				{"tigera-elasticsearch-metrics", "tigera-elasticsearch", "rbac.authorization.k8s.io", "v1", "RoleBinding"},
				{"tigera-elasticsearch-metrics", "", "policy", "v1beta1", "PodSecurityPolicy"},
			}
			Expect(resources).To(HaveLen(len(expectedResources)))
			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			deploy := rtest.GetResource(resources, ElasticsearchMetricsName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			service := rtest.GetResource(resources, ElasticsearchMetricsName, render.ElasticsearchNamespace, "", "v1", "Service").(*corev1.Service)

			expectedService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ElasticsearchMetricsName,
					Namespace: render.ElasticsearchNamespace,
					Labels:    map[string]string{"k8s-app": ElasticsearchMetricsName},
				},
				Spec: corev1.ServiceSpec{
					ClusterIP: "None",
					Selector:  map[string]string{"k8s-app": ElasticsearchMetricsName},
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
									"--web.telemetry-path=/metrics", "--tls.key=/tigera-ee-elasticsearch-metrics-tls/tls.key",
									"--tls.crt=/tigera-ee-elasticsearch-metrics-tls/tls.crt",
									"--ca.crt=/etc/pki/tls/certs/tigera-ca-bundle.crt"},
								Env: []corev1.EnvVar{
									{Name: "FIPS_MODE_ENABLED", Value: "false"},
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
									{Name: "ELASTIC_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
									{Name: "ES_CA_CERT", Value: certificatemanagement.TrustedCertBundleMountPath},
									{Name: "ES_CURATOR_BACKEND_CERT", Value: certificatemanagement.TrustedCertBundleMountPath},
								},
								VolumeMounts: append(
									cfg.TrustedBundle.VolumeMounts(meta.OSTypeLinux),
									cfg.ServerTLS.VolumeMount(meta.OSTypeLinux),
								),
							}},
							ServiceAccountName: ElasticsearchMetricsName,
							Volumes: []corev1.Volume{
								cfg.ServerTLS.Volume(),
								cfg.TrustedBundle.Volume(),
							},
						},
					},
				},
			}
			Expect(service.Spec).To(Equal(expectedService.Spec))
			Expect(deploy.Annotations).To(Equal(expectedDeploy.Annotations))
			Expect(deploy.Spec.Template.Spec.Volumes).To(Equal(expectedDeploy.Spec.Template.Spec.Volumes))
			Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(deploy.Spec.Template.Spec.Containers[0].VolumeMounts).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].VolumeMounts))
			Expect(deploy.Spec.Template.Spec.Containers[0].Args).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].Args))
			Expect(deploy.Spec.Template.Spec.Containers[0].Env).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].Env))
			Expect(deploy.Spec.Template.Spec.Containers[0].Command).To(Equal(expectedDeploy.Spec.Template.Spec.Containers[0].Command))

			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
		})

		It("should render properly when PSP is not supported by the cluster", func() {
			cfg.UsePSP = false
			component := ElasticsearchMetrics(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// Should not contain any PodSecurityPolicies
			for _, r := range resources {
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
			}
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

		Context("allow-tigera rendering", func() {
			policyName := types.NamespacedName{Name: "allow-tigera.elasticsearch-metrics", Namespace: "tigera-elasticsearch"}

			getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
				if scenario.ManagedCluster {
					return nil
				}

				return testutils.SelectPolicyByProvider(scenario, expectedPolicy, expectedPolicyForOpenshift)
			}

			DescribeTable("should render allow-tigera policy",
				func(scenario testutils.AllowTigeraScenario) {
					if scenario.Openshift {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
					} else {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
					}
					component := ElasticsearchMetrics(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				// ES Gateway only renders in the presence of an LogStorage CR and absence of a ManagementClusterConnection CR, therefore
				// does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
				Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			)
		})
	})
})
