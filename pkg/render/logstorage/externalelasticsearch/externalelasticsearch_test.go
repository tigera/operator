// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package externalelasticsearch

import (
	. "github.com/onsi/ginkgo"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("External Elasticsearch rendering tests", func() {
	Context("External Elasticsearch components", func() {
		var installation *operatorv1.InstallationSpec
		var clusterConfig *relasticsearch.ClusterConfig
		var pullSecrets []*corev1.Secret

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}

			clusterConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
			pullSecrets = []*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}}}
		})

		It("should render all resources needed for External Elasticsearch", func() {

			expectedResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRole, Namespace: render.ElasticsearchNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRoleBinding, Namespace: render.ElasticsearchNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.ElasticsearchNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.ElasticsearchNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			}

			component := ExternalElasticsearch(installation, clusterConfig, pullSecrets)
			createResources, _ := component.Objects()

			rtest.ExpectResources(createResources, expectedResources)
		})
	})
})
