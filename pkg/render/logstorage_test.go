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

package render_test

import (
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type resourceTestObj struct {
	name string
	ns   string
	typ  runtime.Object
	f    func(resource runtime.Object)
}

var _ = Describe("Elasticsearch rendering tests", func() {
	Context("Standalone cluster type", func() {
		var logStorage *operator.LogStorage
		var installation *operatorv1.Installation
		replicas := int32(1)
		retention := int32(1)
		var esConfig *render.ElasticsearchClusterConfig
		BeforeEach(func() {
			logStorage = &operator.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operator.LogStorageSpec{
					Nodes: &operator.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
					Indices: &operator.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
					},
				},
				Status: operator.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.Installation{
				Spec: operatorv1.InstallationSpec{
					KubernetesProvider:    operatorv1.ProviderNone,
					Registry:              "testregistry.com/",
					ClusterManagementType: operatorv1.ClusterManagementTypeStandalone,
				},
			}
			esConfig = render.NewElasticsearchClusterConfig("cluster", 1, 1, 1)
		})

		Context("Initial creation", func() {
			It("should render an elasticsearchComponent", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
						ls := resource.(*operatorv1.LogStorage)
						Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
					}},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKWebhookName, render.ECKOperatorNamespace, &corev1.Service{}, nil},
					{render.ECKWebhookConfiguration, "", &admissionv1beta1.ValidatingWebhookConfiguration{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKWebhookSecretName, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchConfigMapName, render.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.ECKEnterpriseTrial, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
				}

				component := render.LogStorage(
					logStorage,
					installation, nil, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					}, true,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})

				resultES := GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				// There are no node selectors in the LogStorage CR, so we expect no node selectors in the Elasticsearch CR.
				nodeSet := resultES.Spec.NodeSets[0]
				Expect(nodeSet.PodTemplate.Spec.NodeSelector).To(BeEmpty())

				// Verify that the default container limist/requests are set.
				esContainer := resultES.Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
				limits := esContainer.Resources.Limits
				resources := esContainer.Resources.Requests

				Expect(limits.Cpu().String()).To(Equal("1"))
				Expect(limits.Memory().String()).To(Equal("4Gi"))
				Expect(resources.Cpu().String()).To(Equal("250m"))
				Expect(resources.Memory().String()).To(Equal("4Gi"))
				Expect(esContainer.Env[0].Value).To(Equal("-Xms1398101K -Xmx1398101K"))

				//Check that the expected config made it's way to the Elastic CR
				Expect(nodeSet.Config.Data).Should(Equal(map[string]interface{}{
					"node.master":                 "true",
					"node.data":                   "true",
					"node.ingest":                 "true",
					"cluster.max_shards_per_node": 10000,
				}))
			})
			It("should render an elasticsearchComponent and delete the Elasticsearch and Kibana ExternalService", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
						ls := resource.(*operatorv1.LogStorage)
						Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
					}},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKWebhookName, render.ECKOperatorNamespace, &corev1.Service{}, nil},
					{render.ECKWebhookConfiguration, "", &admissionv1beta1.ValidatingWebhookConfiguration{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKWebhookSecretName, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchConfigMapName, render.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
				}

				expectedDeleteResources := []resourceTestObj{
					{render.ElasticsearchServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
					{render.KibanaServiceName, render.KibanaNamespace, &corev1.Service{}, nil},
				}

				component := render.LogStorage(
					logStorage,
					installation, nil, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					}, true,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operator.ProviderNone, nil,
					&corev1.Service{
						ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace},
						Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
					},
					&corev1.Service{
						ObjectMeta: metav1.ObjectMeta{Name: render.KibanaServiceName, Namespace: render.KibanaNamespace},
						Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
					}, "cluster.local", false)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, expectedDeleteResources)
			})
		})

		Context("Elasticsearch and Kibana both ready", func() {
			It("should render correctly", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
						ls := resource.(*operatorv1.LogStorage)
						Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
					}},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKWebhookName, render.ECKOperatorNamespace, &corev1.Service{}, nil},
					{render.ECKWebhookConfiguration, "", &admissionv1beta1.ValidatingWebhookConfiguration{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKWebhookSecretName, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchPublicCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.ElasticsearchConfigMapName, render.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaPublicCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchPublicCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.EsCuratorName, render.ElasticsearchNamespace, &batchv1beta.CronJob{}, nil},
					{render.ECKEnterpriseTrial, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
				}

				component := render.LogStorage(
					logStorage,
					installation, nil, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.OperatorNamespace()}},
					}, true,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operator.ProviderNone,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
					},
					nil, nil, "cluster.local", true)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
		})

		Context("Deleting LogStorage", deleteLogStorageTests(operatorv1.ClusterManagementTypeStandalone))

		Context("Updating LogStorage resource", func() {
			It("should create new NodeSet", func() {
				ls := &operator.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operator.LogStorageSpec{
						Nodes: &operator.Nodes{
							Count: 1,
							ResourceRequirements: &corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									"cpu":    resource.MustParse("1"),
									"memory": resource.MustParse("150Mi"),
								},
								Requests: corev1.ResourceList{
									"cpu":     resource.MustParse("1"),
									"memory":  resource.MustParse("150Mi"),
									"storage": resource.MustParse("10Gi"),
								},
							},
						},
					},
				}

				es := &esv1.Elasticsearch{}

				component := render.LogStorage(
					ls,
					installation, es, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					}, true,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

				createResources, _ := component.Objects()

				oldNodeSetName := createResources[22].(*esv1.Elasticsearch).Spec.NodeSets[0].Name

				// update resource requirements
				ls.Spec.Nodes.ResourceRequirements = &corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("150Mi"),
					},
					Requests: corev1.ResourceList{
						"cpu":     resource.MustParse("1"),
						"memory":  resource.MustParse("2Gi"),
						"storage": resource.MustParse("5Gi"),
					},
				}

				updatedComponent := render.LogStorage(
					ls,
					installation, es, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					}, true,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

				updatedResources, _ := updatedComponent.Objects()

				// Check updates to storage requirements are reflected
				Expect(updatedResources[0].(*operatorv1.LogStorage).Spec.Nodes.ResourceRequirements).
					Should(Equal(ls.Spec.Nodes.ResourceRequirements))

				newNodeName := updatedResources[15].(*esv1.Elasticsearch).Spec.NodeSets[0].Name
				Expect(newNodeName).NotTo(Equal(oldNodeSetName))
			})
		})

		It("should render DataNodeSelectors defined in the LogStorage CR", func() {
			logStorage.Spec.DataNodeSelector = map[string]string{
				"k1": "v1",
				"k2": "v2",
			}
			component := render.LogStorage(
				logStorage,
				installation, nil, nil,
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
				}, true,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)
			// Verify that the node selectors are passed into the Elasticsearch pod spec.
			createResources, _ := component.Objects()
			nodeSelectors := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.NodeSelector
			Expect(nodeSelectors["k1"]).To(Equal("v1"))
			Expect(nodeSelectors["k2"]).To(Equal("v2"))
		})
	})

	Context("Managed cluster", func() {
		var installation *operatorv1.Installation
		BeforeEach(func() {
			installation = &operatorv1.Installation{
				Spec: operatorv1.InstallationSpec{
					KubernetesProvider:    operatorv1.ProviderNone,
					Registry:              "testregistry.com/",
					ClusterManagementType: operatorv1.ClusterManagementTypeManaged,
				},
			}
		})
		Context("Initial creation", func() {
			It("creates Managed cluster logstorage components", func() {
				expectedCreateResources := []resourceTestObj{
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{render.ElasticsearchServiceName, render.ElasticsearchNamespace, &corev1.Service{}, func(resource runtime.Object) {
						svc := resource.(*corev1.Service)

						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
						Expect(svc.Spec.ExternalName).Should(Equal(fmt.Sprintf("%s.%s.cluster.local", render.GuardianServiceName, render.GuardianNamespace)))
					}},
					{render.KibanaServiceName, render.KibanaNamespace, &corev1.Service{}, func(resource runtime.Object) {
						svc := resource.(*corev1.Service)

						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
						Expect(svc.Spec.ExternalName).Should(Equal(fmt.Sprintf("%s.%s.cluster.local", render.GuardianServiceName, render.GuardianNamespace)))
					}},
				}

				component := render.LogStorage(
					nil, installation, nil, nil, nil, nil, nil, false,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operator.ProviderNone,
					nil, nil, nil, "cluster.local", true)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
		})
		Context("Deleting LogStorage", deleteLogStorageTests(operatorv1.ClusterManagementTypeManaged))
	})

	Context("NodeSet configuration", func() {
		var logStorage *operator.LogStorage
		var installation *operatorv1.Installation
		var esConfig *render.ElasticsearchClusterConfig

		replicas, retention := int32(1), int32(1)

		BeforeEach(func() {
			logStorage = &operator.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operator.LogStorageSpec{
					Indices: &operator.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
					},
				},
				Status: operator.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.Installation{
				Spec: operatorv1.InstallationSpec{
					KubernetesProvider:    operatorv1.ProviderNone,
					Registry:              "testregistry.com/",
					ClusterManagementType: operatorv1.ClusterManagementTypeStandalone,
				},
			}
			esConfig = render.NewElasticsearchClusterConfig("cluster", 1, 1, 1)
		})
		Context("Node distribution", func() {
			When("the number of Nodes and NodeSets is 3", func() {
				It("creates 3 1 Node NodeSet", func() {
					logStorage.Spec.Nodes = &operator.Nodes{
						Count: 3,
						NodeSets: []operator.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						}, true,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(1)))
					}
				})
			})
			When("the number of Nodes is 2 and the number of NodeSets is 3", func() {
				It("creates 2 1 Node NodeSets", func() {
					logStorage.Spec.Nodes = &operator.Nodes{
						Count: 2,
						NodeSets: []operator.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						}, true,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(1)))
					}
				})
			})
			When("the number of Nodes is 6 and the number of NodeSets is 3", func() {
				It("creates 3 2 Node NodeSets", func() {
					logStorage.Spec.Nodes = &operator.Nodes{
						Count: 6,
						NodeSets: []operator.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						}, true,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(2)))
					}
				})
			})
			When("the number of Nodes is 5 and the number of NodeSets is 6", func() {
				It("creates 2 2 Node NodeSets and 1 1 Node NodeSet", func() {
					logStorage.Spec.Nodes = &operator.Nodes{
						Count: 5,
						NodeSets: []operator.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						}, true,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))

					Expect(nodeSets[0].Count).Should(Equal(int32(2)))
					Expect(nodeSets[1].Count).Should(Equal(int32(2)))
					Expect(nodeSets[2].Count).Should(Equal(int32(1)))
				})
			})
		})

		Context("Node selection", func() {
			When("NodeSets is set but empty", func() {
				It("returns the defualt NodeSet", func() {
					logStorage.Spec.Nodes = &operator.Nodes{
						Count:    2,
						NodeSets: []operator.NodeSet{},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						}, true,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(1))
				})
			})
			When("there is a single selection attribute for a NodeSet", func() {
				It("sets the Node Affinity Elasticsearch cluster awareness attributes with the single selection attribute", func() {
					logStorage.Spec.Nodes = &operator.Nodes{
						Count: 2,
						NodeSets: []operator.NodeSet{
							{
								SelectionAttributes: []operator.NodeSetSelectionAttribute{{
									Name:      "zone",
									NodeLabel: "failure-domain.beta.kubernetes.io/zone",
									Value:     "us-west-2a",
								}},
							},
							{
								SelectionAttributes: []operator.NodeSetSelectionAttribute{{
									Name:      "zone",
									NodeLabel: "failure-domain.beta.kubernetes.io/zone",
									Value:     "us-west-2b",
								}},
							},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						}, true,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					Expect(nodeSets[0].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{{
									Key:      "failure-domain.beta.kubernetes.io/zone",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"us-west-2a"},
								}},
							}},
						},
					}))
					Expect(nodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2a",
						"cluster.routing.allocation.awareness.attributes": "zone",
					}))

					Expect(nodeSets[1].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{{
									Key:      "failure-domain.beta.kubernetes.io/zone",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"us-west-2b"},
								}},
							}},
						},
					}))
					Expect(nodeSets[1].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2b",
						"cluster.routing.allocation.awareness.attributes": "zone",
					}))
				})
			})
			When("there are multiple selection attributes for a NodeSet", func() {
				It("combines to attributes for the Node Affinity and Elasticsearch cluster awareness attributes", func() {
					logStorage.Spec.Nodes = &operator.Nodes{
						Count: 2,
						NodeSets: []operator.NodeSet{
							{
								SelectionAttributes: []operator.NodeSetSelectionAttribute{
									{
										Name:      "zone",
										NodeLabel: "failure-domain.beta.kubernetes.io/zone",
										Value:     "us-west-2a",
									},
									{
										Name:      "rack",
										NodeLabel: "some-rack-label.kubernetes.io/rack",
										Value:     "rack1",
									},
								},
							},
							{
								SelectionAttributes: []operator.NodeSetSelectionAttribute{
									{
										Name:      "zone",
										NodeLabel: "failure-domain.beta.kubernetes.io/zone",
										Value:     "us-west-2b",
									},
									{
										Name:      "rack",
										NodeLabel: "some-rack-label.kubernetes.io/rack",
										Value:     "rack1",
									},
								},
							},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						}, true,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operator.ProviderNone, nil, nil, nil, "cluster.local", true)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					Expect(nodeSets[0].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "failure-domain.beta.kubernetes.io/zone",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"us-west-2a"},
									},
									{
										Key:      "some-rack-label.kubernetes.io/rack",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"rack1"},
									},
								},
							}},
						},
					}))
					Expect(nodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2a",
						"node.attr.rack":              "rack1",
						"cluster.routing.allocation.awareness.attributes": "zone,rack",
					}))

					Expect(nodeSets[1].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{
								{
									MatchExpressions: []corev1.NodeSelectorRequirement{{
										Key:      "failure-domain.beta.kubernetes.io/zone",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"us-west-2b"},
									},
										{
											Key:      "some-rack-label.kubernetes.io/rack",
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{"rack1"},
										},
									},
								}},
						},
					}))
					Expect(nodeSets[1].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2b",
						"node.attr.rack":              "rack1",
						"cluster.routing.allocation.awareness.attributes": "zone,rack",
					}))
				})
			})
		})
	})
})

var deleteLogStorageTests = func(clusterType operatorv1.ClusterManagementType) func() {
	return func() {
		var logStorage *operator.LogStorage
		var installation *operatorv1.Installation
		replicas := int32(1)
		retention := int32(1)
		var esConfig *render.ElasticsearchClusterConfig
		BeforeEach(func() {
			t := metav1.Now()

			logStorage = &operator.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "tigera-secure",
					DeletionTimestamp: &t,
				},
				Spec: operator.LogStorageSpec{
					Nodes: &operator.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
					Indices: &operator.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
					},
				},
				Status: operator.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.Installation{
				Spec: operatorv1.InstallationSpec{
					KubernetesProvider:    operatorv1.ProviderNone,
					Registry:              "testregistry.com/",
					ClusterManagementType: clusterType,
				},
			}
			esConfig = render.NewElasticsearchClusterConfig("cluster", 1, 1, 1)
		})
		It("returns Elasticsearch and Kibana CR's to delete and keeps the finalizers on the LogStorage CR", func() {
			expectedCreateResources := []resourceTestObj{
				{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
					ls := resource.(*operatorv1.LogStorage)
					Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
				}},
			}

			expectedDeleteResources := []resourceTestObj{
				{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
				{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
			}

			component := render.LogStorage(
				logStorage,
				installation,
				&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
				&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace}},
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}},
				}, true,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operator.ProviderNone,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
				},
				nil, nil, "cluster.local", true)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, expectedDeleteResources)
		})
		It("doesn't return anything to delete when Elasticsearch and Kibana have their deletion times stamps set and the LogStorage finalizers are still set", func() {
			expectedCreateResources := []resourceTestObj{
				{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
					ls := resource.(*operatorv1.LogStorage)
					Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
				}},
			}

			t := metav1.Now()
			component := render.LogStorage(
				logStorage,
				installation,
				&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace, DeletionTimestamp: &t}},
				&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace, DeletionTimestamp: &t}},
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}},
				}, true,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operator.ProviderNone,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
				},
				nil, nil, "cluster.local", true)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, []resourceTestObj{})
		})
		It("removes the finalizers from LogStorage if Elasticsearch and Kibana are both nil", func() {
			expectedCreateResources := []resourceTestObj{
				{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
					ls := resource.(*operatorv1.LogStorage)
					Expect(ls.Finalizers).ShouldNot(ContainElement(render.LogStorageFinalizer))
				}},
			}

			component := render.LogStorage(
				logStorage,
				installation,
				nil, nil,
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}},
				}, true,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operator.ProviderNone,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
				},
				nil, nil, "cluster.local", true)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, []resourceTestObj{})
		})
	}
}

func compareResources(resources []runtime.Object, expectedResources []resourceTestObj) {
	Expect(len(resources)).To(Equal(len(expectedResources)))
	for i, expectedResource := range expectedResources {
		resource := resources[i]
		actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
		actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()

		Expect(actualName).To(Equal(expectedResource.name), fmt.Sprintf("Rendered resource has wrong name (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(actualNS).To(Equal(expectedResource.ns), fmt.Sprintf("Rendered resource has wrong namespace (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(resource).Should(BeAssignableToTypeOf(expectedResource.typ))
		if expectedResource.f != nil {
			expectedResource.f(resource)
		}
	}
}

func getElasticsearch(resources []runtime.Object) *esv1.Elasticsearch {
	resource := GetResource(resources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch")
	Expect(resource).ShouldNot(BeNil())

	return resource.(*esv1.Elasticsearch)
}
