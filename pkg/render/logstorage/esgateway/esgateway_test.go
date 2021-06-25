package esgateway

import (
	"fmt"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type resourceTestObj struct {
	name string
	ns   string
	typ  runtime.Object
	f    func(resource runtime.Object)
}

var _ = Describe("ES Gateway rendering tests", func() {
	Context("ES Gateway deployment", func() {
		var logStorage *operatorv1.LogStorage
		var installation *operatorv1.InstallationSpec
		clusterDomain := "cluster.local"

		BeforeEach(func() {
			logStorage = &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{},
			}

			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}
		})

		It("should render an ES Gateway deployment and all supporting resources", func() {
			expectedResources := []resourceTestObj{
				{ElasticsearchUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{render.KibanaInternalCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{render.ElasticsearchServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
				{render.KibanaServiceName, render.KibanaNamespace, &corev1.Service{}, nil},
				{render.KibanaServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
				{RoleName, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
				{RoleName, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				{ServiceAccountName, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
				{DeploymentName, render.ElasticsearchNamespace, &appsv1.Deployment{}, nil},
			}

			component := EsGateway(
				logStorage,
				installation,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.ElasticsearchAdminUserSecret,
						Namespace: render.ElasticsearchNamespace,
					},
					Data: map[string][]byte{
						"elastic": []byte("password"),
					},
				},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaInternalCertSecret, Namespace: rmeta.OperatorNamespace()}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.InternalCertSecret, Namespace: render.ElasticsearchNamespace}},
				clusterDomain,
			)

			createResources, _ := component.Objects()
			compareResources(createResources, expectedResources)
		})

	})
})

func compareResources(resources []client.Object, expectedResources []resourceTestObj) {
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
