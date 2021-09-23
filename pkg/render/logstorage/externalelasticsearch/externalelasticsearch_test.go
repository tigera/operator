// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package externalelasticsearch

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
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

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}

			clusterConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
		})

		It("should render all resources needed for External Elasticsearch", func() {
			expectedResources := []resourceTestObj{
				{render.ElasticsearchNamespace, "", &corev1.Namespace{}},
				{relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace(), &corev1.ConfigMap{}},
				{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}},
				{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}},
			}

			component := ExternalElasticsearch(installation, clusterConfig)
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
