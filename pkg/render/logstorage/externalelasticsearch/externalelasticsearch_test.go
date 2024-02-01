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
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
)

type resourceTestObj struct {
	name string
	ns   string
	typ  runtime.Object
}

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
			expectedResources := []resourceTestObj{
				{render.ElasticsearchNamespace, "", &corev1.Namespace{}},
				{relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &corev1.ConfigMap{}},
				{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}},
				{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}},
				{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}},
			}

			component := ExternalElasticsearch(installation, clusterConfig, pullSecrets)
			createResources, _ := component.Objects()

			Expect(len(createResources)).To(Equal(len(expectedResources)))
			for i, expectedResource := range expectedResources {
				Expect(createResources[i].GetName()).To(Equal(expectedResource.name))
				Expect(createResources[i].GetNamespace()).To(Equal(expectedResource.ns))
				Expect(createResources[i]).Should(BeAssignableToTypeOf(expectedResource.typ))
			}
		})
	})
})
