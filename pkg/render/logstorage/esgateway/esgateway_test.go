package esgateway

import (
	"fmt"

	"github.com/tigera/operator/pkg/common"

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
		replicaCount := int32(1)
		clusterDomain := "cluster.local"

		BeforeEach(func() {
			logStorage = &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					EsGatewayReplicaCount: &replicaCount,
				},
			}

			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}
		})

		It("should render an ES Gateway deployment and all supporting resources", func() {
			expectedResources := []resourceTestObj{
				{EsGatewayElasticUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{EsGatewayTLSSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
				{EsGatewayTLSSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{EsGatewayElasticPublicCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
				{EsGatewayElasticPublicCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{EsGatewayKibanaPublicCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
				{EsGatewayKibanaPublicCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
				{render.KibanaPublicCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{EsGatewayElasticServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
				{EsGatewayKibanaServiceName, render.KibanaNamespace, &corev1.Service{}, nil},
				{EsGatewayKibanaServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
				{EsGatewayRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
				{EsGatewayRole, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				{EsGatewayServiceAccountName, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
				{"tigera-es-gateway:csr-creator", "", &rbacv1.ClusterRoleBinding{}, nil},
				{EsGatewayName, render.ElasticsearchNamespace, &appsv1.Deployment{}, nil},
			}

			component := EsGateway(
				logStorage,
				installation,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.ElasticsearchAdminUserSecret,
						Namespace: render.ElasticsearchNamespace,
					},
					Data: map[string][]byte{
						"elastic": []byte("password"),
					},
				},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      EsGatewayTLSSecret,
						Namespace: rmeta.OperatorNamespace(),
					},
					Data: map[string][]byte{
						EsGatewaySecretCertName: []byte("crt"),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.ElasticsearchKubeControllersUserSecret,
						Namespace: common.CalicoNamespace,
					},
					Data: map[string][]byte{
						"username": []byte("username"),
						"password": []byte("password"),
					},
				},
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
