package logstorage_test

import (
	"context"
	"os"

	esalpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/elasticsearch/v1alpha1"
	kibanav1alpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/kibana/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/apis"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/logstorage"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Log storage controller", func() {
	var (
		scheme *runtime.Scheme
	)
	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
	})
	Context("Managed Cluster", func() {
		var (
			cli            client.Client
			resolvConfPath string
		)
		BeforeEach(func() {
			cli = fake.NewFakeClientWithScheme(scheme)
			dir, err := os.Getwd()
			if err != nil {
				panic(err)
			}
			resolvConfPath = dir + "/testdata/resolv.conf"
			ctx := context.Background()
			Expect(cli.Create(ctx, &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.TigeraSecureEnterprise,
				},
				Spec: operatorv1.InstallationSpec{
					Variant:               operatorv1.TigeraSecureEnterprise,
					ClusterManagementType: operatorv1.ClusterManagementTypeManaged,
				},
			})).ShouldNot(HaveOccurred())
		})
		It("tests that the ExternalService is setup", func() {
			r, err := logstorage.NewReconcilerWithShims(cli, scheme, status.New(cli, "log-storage"), operatorv1.ProviderNone, resolvConfPath)
			Expect(err).ShouldNot(HaveOccurred())
			ctx := context.Background()

			_, err = r.Reconcile(reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			svc := &corev1.Service{}
			Expect(
				cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace}, svc),
			).ShouldNot(HaveOccurred())

			Expect(svc.Spec.ExternalName).Should(Equal("tigera-guardian.tigera-guardian.svc.othername.local"))
			Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
		})
		It("tests an error is returned if the LogStorage resource exists", func() {
			r, err := logstorage.NewReconcilerWithShims(cli, scheme, status.New(cli, "log-storage"), operatorv1.ProviderNone, resolvConfPath)
			Expect(err).ShouldNot(HaveOccurred())
			ctx := context.Background()

			Expect(cli.Create(ctx, &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
			})).ShouldNot(HaveOccurred())

			_, err = r.Reconcile(reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(Equal("cluster type is Managed but logstorage still exists"))
		})
	})
	Context("Non managed cluster", func() {
		var (
			cli            client.Client
			resolvConfPath string
		)
		BeforeEach(func() {
			cli = fake.NewFakeClientWithScheme(scheme)
			dir, err := os.Getwd()
			if err != nil {
				panic(err)
			}
			resolvConfPath = dir + "/testdata/resolv.conf"
			ctx := context.Background()
			Expect(cli.Create(ctx, &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.TigeraSecureEnterprise,
				},
				Spec: operatorv1.InstallationSpec{
					Variant:               operatorv1.TigeraSecureEnterprise,
					ClusterManagementType: operatorv1.ClusterManagementTypeManagement,
				},
			})).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, &storagev1.StorageClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: render.ElasticsearchStorageClass,
				},
			})).ShouldNot(HaveOccurred())

			Expect(cli.Create(ctx, &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					Nodes: &operatorv1.Nodes{
						Count: int64(1),
					},
				},
			})).ShouldNot(HaveOccurred())
		})
		It("tests elasticsearch is setup correctly", func() {
			r, err := logstorage.NewReconcilerWithShims(cli, scheme, status.New(cli, "log-storage"), operatorv1.ProviderNone, resolvConfPath)
			Expect(err).ShouldNot(HaveOccurred())
			ctx := context.Background()

			_, err = r.Reconcile(reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(
				cli.Get(ctx, client.ObjectKey{Name: render.ECKOperatorName, Namespace: render.ECKOperatorNamespace}, &apps.StatefulSet{}),
			).ShouldNot(HaveOccurred())

			Expect(
				cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, &esalpha1.Elasticsearch{}),
			).ShouldNot(HaveOccurred())

			Expect(
				cli.Get(ctx, client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}, &kibanav1alpha1.Kibana{}),
			).ShouldNot(HaveOccurred())
		})
	})
})
