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

	esv1alpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/elasticsearch/v1alpha1"
	kbv1alpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/kibana/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
			// Initialize a default logStorage to use. Each test can override this to its
			// desired configuration.
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
					{"tigera-secure", "", &operatorv1.LogStorage{}, nil},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKWebhookSecretName, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchConfigMapName, render.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1alpha1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1alpha1.Kibana{}, nil},
				}

				component := render.Elasticsearch(
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
					}, operator.ProviderNone, nil, nil, "cluster.local")

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
			It("should render an elasticsearchComponent and delete the ExternalService", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, nil},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKWebhookSecretName, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchConfigMapName, render.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1alpha1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1alpha1.Kibana{}, nil},
				}

				expectedDeleteResources := []resourceTestObj{
					{render.ElasticsearchServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
				}

				component := render.Elasticsearch(
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
					}, "cluster.local")

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, expectedDeleteResources)
			})
		})

		Context("Elasticsearch and Kibana both ready", func() {
			It("should render correctly", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, nil},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKWebhookSecretName, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchPublicCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchConfigMapName, render.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1alpha1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaPublicCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1alpha1.Kibana{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchPublicCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.EsCuratorName, render.ElasticsearchNamespace, &batchv1beta.CronJob{}, nil},
				}

				component := render.Elasticsearch(
					logStorage,
					installation, nil, nil,
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
					nil, "cluster.local")

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
		})

		Context("Deleting LogStorage", func() {
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
						ClusterManagementType: operatorv1.ClusterManagementTypeStandalone,
					},
				}
				esConfig = render.NewElasticsearchClusterConfig("cluster", 1, 5)
			})
		})
	})

})

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
