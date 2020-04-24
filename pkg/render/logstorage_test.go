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
			esConfig = render.NewElasticsearchClusterConfig("cluster", 1, 5)
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

				// There are no node selectors in the LogStorage CR, so we expect no node selectors in the Elasticsearch CR.
				Expect(createResources[15].(*esv1.Elasticsearch).Spec.NodeSets[0].PodTemplate.Spec.NodeSelector).To(BeEmpty())
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

				oldNodeSetName := createResources[15].(*esv1.Elasticsearch).Spec.NodeSets[0].Name

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
			createResouces, _ := component.Objects()
			nodeSelectors := createResouces[15].(*esv1.Elasticsearch).Spec.NodeSets[0].PodTemplate.Spec.NodeSelector
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
			esConfig = render.NewElasticsearchClusterConfig("cluster", 1, 5)
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
